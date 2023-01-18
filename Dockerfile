FROM        golang:1.20rc3 as builder
WORKDIR     /go/src/app
COPY        . ./
RUN         CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ip-auth-proxy .

FROM        scratch
COPY        --from=builder /go/src/app/ip-auth-proxy /
ENTRYPOINT  [ "/ip-auth-proxy" ]
