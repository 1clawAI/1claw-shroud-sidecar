# Base images are pinned by digest, not by tag.
#
# `node:22-slim` and friends are moving tags: the same line can resolve to
# different userland in two builds a week apart, which makes a build
# unreproducible and means an upstream compromise arrives without any change
# here. The tag is kept beside the digest for readability; the digest is what
# docker actually resolves.
#
# renovate.json keeps these current -- a pin nobody updates is its own problem,
# because it freezes known-bad versions in place.
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /shroud-sidecar .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/1clawAI/1claw-shroud-sidecar"
LABEL org.opencontainers.image.version="${VERSION}"
COPY --from=builder /shroud-sidecar /shroud-sidecar
USER nonroot:nonroot
EXPOSE 8080 8081
ENTRYPOINT ["/shroud-sidecar"]
