# ip-auth-proxy
A tiny reverse proxy that authenticates requests by source address.

## Configuration

Via command-line arguments:

    Usage of ip-auth-proxy:
    -authorized-ips string
            ips authorized to access (default "127.0.0.1/32")
    -listen-port int
            port to listen on (default 8000)
    -upstream-url string
            upstream url (default "http://127.0.0.1:8080")
    -verbose
            be verbose

Environment variables:

    LISTEN_PORT       (default: 8000)
	VERBOSE           (default: false)
	AUTHORIZED_IPS    (default: 127.0.0.1/32)
	UPSTREAM_URL      (default: http://127.0.0.1:8080)

AUTHORIZED_IPS is a comma-separated list of
[CIDR notations](https://pkg.go.dev/net#ParseCIDR), e.g. `192.0.2.0/24,2001:db8::/32`.


## Docker Image
The official docker image is located at
[Docker Hub](https://hub.docker.com/r/nxcc/ip-auth-proxy)
