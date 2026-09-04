# Pushing this to GitHub

The repository is already a git repository with a commit on `main`. You are
publishing it, not creating it.

## 1. Publish

**With the GitHub CLI** (simplest — it creates the repo and pushes in one step):

```bash
cd ~/dev/mal-assessment
gh auth status || gh auth login          # only if you are not already signed in
gh repo create accounts-api-security --public --source=. --remote=origin --push
```

**Without `gh`** — create an empty **public** repo named `accounts-api-security`
on github.com first (no README, no .gitignore, no licence — the repo already has
them), then:

```bash
cd ~/dev/mal-assessment
git remote add origin https://github.com/<your-username>/accounts-api-security.git
git push -u origin main
```

If HTTPS asks for a password, that is a personal access token, not your account
password: github.com → Settings → Developer settings → Personal access tokens →
Fine-grained → **Contents: read and write** on this one repository.

## 2. Check it opens for a stranger

The brief asks for this explicitly, and it is the single most common way a
submission fails before anyone reads it.

```bash
open -na "Google Chrome" --args --incognito "https://github.com/<your-username>/accounts-api-security"
```

You should see the README with no sign-in prompt. If you get a 404, the repo is
private: Settings → General → Danger Zone → **Change visibility → Public**.

## 3. Watch the pipeline go green

Pushing to `main` triggers two workflows. Give them about four minutes, then open
the **Actions** tab.

**`build-release`** — this one is the point. On a repo with no AWS account and no
secrets it still: builds the image, generates an SPDX SBOM from the *pushed digest*,
keyless-signs it through Sigstore, attaches the SBOM as an attestation, and then
**verifies its own signature and attestation** before declaring success. The job
summary prints the digest and the exact `cosign verify` command a reviewer can run
themselves. That green tick is the difference between a supply chain that is
designed and one that demonstrably works.

**`security-gates`** — waiver integrity (including the two negative fixtures),
full-history secret scan, SCA, SAST (advisory), IaC, and the policy test suite.

### If something is red

| symptom | what it means | fix |
|---|---|---|
| `build-release` fails at the GHCR push with `denied` | the package does not exist yet and defaults to private | it usually succeeds on the second run; otherwise create the package, or Settings → Actions → General → Workflow permissions → **Read and write** |
| `attest` fails with a Sigstore/Rekor timeout | the public-good instance was slow | re-run the job. The job already wraps every cosign call in `timeout` with three retries precisely so it fails fast instead of hanging — the limitation is written up in `docs/02-build-integrity.md` |
| `waiver-integrity` fails with `SEC-2041 ... EXPIRED` | you are running after **2026-09-27** | this is the control working, not a bug. It is documented in the README. Either leave it (and say so — it demonstrates fail-closed behaviour) or open a renewal PR |
| `secrets` fails | gitleaks found something in history | do not rewrite history. Rotate whatever it found first — the job prints exactly that |

A red `sast` job never blocks; it is advisory by design until 2026-10-15.

## 4. Two optional settings that make the repo match its own documentation

Neither is required for the submission, and the repo is honest about them being
settings rather than files. Turning them on takes a minute and makes the claims in
`ASSUMPTIONS.md` true rather than assumed.

**Branch protection** — Settings → Branches → Add rule for `main`:
require a pull request, require review from Code Owners, and require the status
check **`gate`**. That single check is the one `security-gates.yml` rolls all the
blocking gates into, so there is one thing to require and one place to look.

**The AWS path** — Settings → Secrets and variables → Actions → Variables → New:
`AWS_ENABLED` = `true`. Only do this if you have actually created the roles in
`iam/`; otherwise the ECR and EKS steps will fail, and the default (skipped, with
a note in the job summary) is the honest state.

## 5. Then fill in the form

Everything the form asks for is in [`SUBMISSION-GUIDE.md`](SUBMISSION-GUIDE.md),
field by field, with the exact file for each. The repository URL from step 1 goes
in the "Git repository (link or archive)" field.

## If you would rather not publish it

The form accepts an archive. From the repo root:

```bash
cd ~/dev && zip -qr mal-assessment.zip mal-assessment && ls -lh mal-assessment.zip
```

That keeps the git history, so a reviewer can still see the commit. You lose the
green Actions run, which is a real loss here — it is the evidence that the supply
chain works rather than merely being described. Publish if you can.
