FROM golang:1

ADD . /root/popub
RUN go get -C /root/popub -u -v ./cmd/popub-local ./cmd/popub-relay && \
    go install -C /root/popub ./cmd/popub-local ./cmd/popub-relay

# Usage:
#   docker run --rm --net=host m13253/popub popub-local localhost:80 my.server.addr:46687 SomePassphrase
#   docker run --rm --net=host m13253/popub popub-relay :46687 :8080 SomePassphrase
