# Blind relay. Build context: this directory (server/).
#   docker build -t calc-relay .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay \
 && mkdir -p /out/data

# No shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relay /relay
# Named volumes inherit this ownership on first mount.
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/relay", "-addr", ":8080", "-db", "/data/relay.db", "-attachments", "/data/attachments"]
