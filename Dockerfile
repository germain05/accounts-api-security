# Minimal, distroless, non-root. Referenced by the build pipeline and by several
# claims elsewhere in this repo — the Falco rules assume there is no shell in the
# image, and the SCA threshold assumes the OS layer is nearly empty.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY app/go.mod ./
RUN go mod download
COPY app/ ./
# Static build: no libc at runtime, so the distroless base below can be `static`.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w -buildid=" -o /out/accounts-api ./...

# `static` rather than `base`: no shell, no package manager, no libc. This is what
# makes "any process other than the service binary is an incident" a defensible
# Falco rule rather than an aspiration.
FROM gcr.io/distroless/static-debian12:nonroot
USER 10001:10001
COPY --from=build /out/accounts-api /accounts-api
EXPOSE 8080
ENTRYPOINT ["/accounts-api"]
