FROM golang:1.24-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /shroud-sidecar .

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/1clawAI/1claw-shroud-sidecar"
LABEL org.opencontainers.image.version="${VERSION}"
COPY --from=builder /shroud-sidecar /shroud-sidecar
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/shroud-sidecar"]
