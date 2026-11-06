ARG GO_VERSION=1.26.10
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath \
      -ldflags="-s -w -X main.buildVersion=$VERSION -X main.buildCommit=$COMMIT" -o /out/p2wlan-control . \
 && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath \
      -ldflags="-s -w -X main.buildVersion=$VERSION -X main.buildCommit=$COMMIT" -o /out/p2wlan-relay ./relay \
 && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/p2wlan-config ./cmd/p2wlan-config \
 && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/p2wlan-db ./cmd/p2wlan-db

FROM debian:bookworm-slim

ARG VERSION=dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="P2WLAN Server" \
      org.opencontainers.image.source="https://github.com/yhan-sun/p2wlan" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$COMMIT"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -r -u 10001 p2wlan \
  && mkdir -p /data \
  && chown -R p2wlan:p2wlan /data

COPY --from=build /out/ /usr/local/bin/
WORKDIR /data

ENV PORT=18080
ENV DB_PATH=/data/p2pnet.db
ENV LOG_UPLOAD_DIR=/data/log-uploads
EXPOSE 18080 18081

USER p2wlan
ENTRYPOINT ["/usr/local/bin/p2wlan-control"]
