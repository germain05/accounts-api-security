# IAM policies

Four policies and one deliberately-preserved bad one. Threats **T1** (CI/CD
identity abuse) and **T2** (pod identity over-permission).

> **Why the rationale lives here and not in the JSON.**
> An IAM policy document accepts only `Version`, `Id` and `Statement` at the top
> level. A `_comment` key — the usual trick for annotating policy JSON — is not
> ignored by AWS; `iam:CreatePolicy` and `iam:UpdateAssumeRolePolicy` reject the
> whole document with `MalformedPolicyDocument`. So every file in this directory
> is byte-for-byte appliable as it stands, and the commentary is here.
> `scripts/run-policy-tests.sh` asserts that property on every JSON in this
> directory, so it cannot regress quietly.

| file | attaches to | purpose |
|---|---|---|
| [`pod-identity-policy.json`](pod-identity-policy.json) | `accounts-api-pod` (IRSA) | **Section 4c answer.** The policy I would actually ship. |
| [`pod-identity-policy-original.json`](pod-identity-policy-original.json) | — | The policy in production **today**, kept verbatim as the negative fixture so the "before" is executable rather than quoted. |
| [`github-oidc-trust-policy.json`](github-oidc-trust-policy.json) | `gha-accounts-api-deploy` (prod, `123456789012`) | **Section 2 answer.** Who may assume the deploy role. |
| [`github-oidc-trust-policy-build.json`](github-oidc-trust-policy-build.json) | `gha-accounts-api-ecr-push` (build, `210987654321`) | Weaker on purpose: may push an image, may not touch prod. |
| [`external-secrets-policy.json`](external-secrets-policy.json) | the External Secrets / CSI driver SA | Reads the secrets it is asked to sync. |

---

## `pod-identity-policy.json` — the rewrite

**What the original allowed.** `Allow` + `NotAction: ["iam:DeleteRole",
"iam:DeleteUser"]` + `Resource: "*"` is not a deny-list with two holes; it is an
**allow-list of every action in AWS except two**. It permits `iam:CreateUser`,
`iam:AttachUserPolicy`, `sts:AssumeRole`, `s3:GetObject` on every bucket in the
account, `cloudtrail:StopLogging`, `kms:Decrypt` on every key, and
`secretsmanager:GetSecretValue` on every other team's secrets. RCE in this pod was
account takeover, and the second statement's `Resource: ""` was dead weight — the
first had already granted it.

**One line on what my version denies that the original allowed:** everything
except reading one named database secret, decrypting it through one KMS key via
Secrets Manager only, and reading two Kafka topics — and it additionally denies,
explicitly and unconditionally, all IAM/STS mutation and role chaining, any
tampering with CloudTrail/GuardDuty/Config/log retention, any call outside
`ap-south-1`, and any use of the credential from outside our two VPC endpoints.

**The four conditions that do the real work**, none of which the original had:

* `secretsmanager:VersionStage = AWSCURRENT` — a stolen credential cannot walk
  back through `AWSPREVIOUS` to recover the pre-rotation password. This is what
  makes the emergency rotation in `docs/06-secrets-rotation.md` actually final.
* `kms:ViaService = secretsmanager.ap-south-1.amazonaws.com` plus
  `kms:EncryptionContext:SecretARN` — the key can decrypt *that secret through
  that service*, not arbitrary ciphertext the attacker brings. Without the
  encryption-context condition, `kms:Decrypt` on the key is a general-purpose
  decryption oracle for everything else encrypted under it.
* `aws:RequestedRegion != ap-south-1` → Deny — data residency (RBI) enforced in
  the identity layer, so it survives a misconfigured deployment rather than
  depending on one. `iam:*`, `sts:*` and `kms:DescribeKey` are in `NotAction`
  because they are global endpoints and would otherwise deny themselves.
* `aws:SourceVpce` → Deny outside our two endpoints, guarded by
  `aws:ViaAWSService = false` so AWS's own service-to-service calls are not
  broken. This is the condition that makes an exfiltrated credential inert on the
  attacker's own machine.

**What it still does not stop.** The pod is *supposed* to read the customer
database, so a compromised pod using this policy exactly as intended still reaches
the whole dataset. That is blast-radius scenario (a) in `DECISIONS.md` and the
undetected path in §4 — no IAM policy closes it, because the permission is the
requirement.

---

## `github-oidc-trust-policy.json` — the deploy role

Four conditions, all `StringEquals`, all mandatory:

| claim | value | what it denies |
|---|---|---|
| `aud` | `sts.amazonaws.com` | tokens minted for any other audience |
| `sub` | `repo:example-bank/accounts-api:environment:production` | every other repo, every branch, every tag, every fork, every pull request, and any run of *this* repo that has not passed the `production` GitHub Environment's reviewers — the claim is only minted once approval is granted |
| `job_workflow_ref` | `…/.github/workflows/build-release.yml@refs/heads/main` | a **new or renamed workflow file** in this same repo. This is the condition that answers blast-radius scenario (b): an attacker who adds `evil.yml` gets a valid OIDC token that STS refuses |
| `repository_owner_id` | `123456` | the repo being deleted or transferred and its `owner/name` re-registered by someone else — the numeric id cannot be re-created |

**What it does not deny:** a modification to `build-release.yml` itself, merged to
`main` and approved in the `production` environment. That is a two-person-review
problem, not an IAM one, and it is why `DECISIONS.md` §6 lists hardware-backed
commit signing as the real control for (b).

**Wildcard note.** There is deliberately no `StringLike` anywhere in this file. A
`sub` of `repo:example-bank/accounts-api:*` is the most common shape in the wild
and it accepts *every branch and every pull request in the repo*, which is
equivalent to no scoping at all for an attacker who can open a PR.

**Applying it.** The `sub` and `job_workflow_ref` values are environment-specific
by design; in a real rollout they are rendered by Terraform from the repo and
workflow names rather than hand-copied, so renaming the workflow file updates the
trust policy in the same change. Nothing here was applied against a real account —
see `ASSUMPTIONS.md`.

---

## `github-oidc-trust-policy-build.json` — the build role

Same shape, deliberately weaker: it is scoped to the repository and workflow but
**not** to the `production` environment, because the build job must run on every
push to `main` without waiting for a human approval. It can push to ECR in the
build account and it can do nothing in the production account. The split is the
point: the credential that runs unattended on every merge is not the credential
that can reach production.

---

## `external-secrets-policy.json` — the operator

A **separate role from the pod's**, which is the whole design. The operator can
read the secrets it is asked to sync; the pod can read exactly one. Collapsing the
two is the common shortcut and it silently undoes every least-privilege decision
in `pod-identity-policy.json`, because the workload then inherits the operator's
breadth. See `docs/06-secrets-rotation.md` for the delivery path.
