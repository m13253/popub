# build stage
FROM golang:1-buster as builder
ARG CGO_ENABLED=0
WORKDIR /root/popub
COPY . /root/popub/
RUN go build -ldflags "-s -w" github.com/m13253/popub/cmd/popub-relay \
    && go build -ldflags "-s -w" github.com/m13253/popub/cmd/popub-local

# production stage
FROM scratch
COPY --from=builder /root/popub/popub-relay /usr/local/bin/popub-relay
COPY --from=builder /root/popub/popub-local /usr/local/bin/popub-local
CMD ["popub-relay"]
