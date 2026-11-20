# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
# extra_ca: optional CA bundle for builds behind a TLS-intercepting proxy.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/demo-rp ./examples/demo-rp

FROM scratch
COPY --from=builder /out/demo-rp /demo-rp
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/demo-rp"]
