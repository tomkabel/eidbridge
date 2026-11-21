# syntax=docker/dockerfile:1
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
ARG VERSION=dev
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum* ./
# extra_ca: optional CA bundle for builds behind a TLS-intercepting proxy.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/tomkabel/eidbridge/internal/version.Version=${VERSION}" -o /out/eidbridge ./cmd/eidbridge

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.title="eidbridge" \
      org.opencontainers.image.description="Unofficial, community-maintained Smart-ID RP API v3 to OpenID Connect bridge. Not affiliated with, endorsed by or certified by the operators of Smart-ID, Mobile-ID, the Estonian ID-card or any EUDI Wallet." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tomkabel/eidbridge" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/eidbridge /eidbridge
COPY trust/ /trust/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/eidbridge"]
