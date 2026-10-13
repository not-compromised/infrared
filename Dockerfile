FROM golang:1.26.9-alpine AS builder
LABEL stage=intermediate
COPY . /infrared
WORKDIR /infrared/cmd/infrared
ENV GO111MODULE=on
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo -o /main .

FROM scratch
LABEL maintainer="Hendrik Jonas Schlehlein <hendrik.schlehlein@gmail.com>"
WORKDIR /
COPY --from=builder /main ./
ENTRYPOINT [ "./main" ]
