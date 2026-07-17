FROM golang:1.23-bookworm AS build

WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/p2wlan-control .

FROM debian:bookworm-slim

RUN useradd -r -u 10001 p2wlan \
  && mkdir -p /data \
  && chown -R p2wlan:p2wlan /data

COPY --from=build /out/p2wlan-control /usr/local/bin/p2wlan-control

ENV PORT=18080
ENV DB_PATH=/data/p2pnet.db
EXPOSE 18080

USER p2wlan
ENTRYPOINT ["/usr/local/bin/p2wlan-control"]
