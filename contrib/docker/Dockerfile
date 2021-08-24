# build stage
FROM golang:1-buster as builder

WORKDIR /root/popub
COPY . /root/popub/
RUN go build -ldflags "-s -w" github.com/m13253/popub/cmd/popub-relay
    && go build -ldflags "-s -w" github.com/m13253/popub/cmd/popub-local

# production stage
FROM scratch
COPY --from=builder /root/popub/popub-relay /root/popub/popub-local /
CMD ["/popub-relay"]
