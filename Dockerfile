# Build: single static binary, no CGO.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /server ./cmd/server

# Run: minimal image, non-root.
FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
WORKDIR /app
COPY --from=build /server /app/server
COPY data/reference-manifest.json /app/data/reference-manifest.json
# Provide KEYS_FILE and KMS_MASTER_KEY at runtime:
#   docker run -e KMS_MASTER_KEY=... -v /path/to/keys.json:/app/data/keys.json:ro \
#     -p 8080:8080 composite-attestation-combiner
ENV KEYS_FILE=/app/data/keys.json \
    REFERENCE_MANIFEST=/app/data/reference-manifest.json \
    LISTEN_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/app/server"]
