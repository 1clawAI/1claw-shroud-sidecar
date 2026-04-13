FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /shroud-sidecar .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /shroud-sidecar /shroud-sidecar
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/shroud-sidecar"]
