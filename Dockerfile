FROM golang:1.21-alpine as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN cd cmd && go build -o dns-server

FROM alpine:latest as server

WORKDIR /app

COPY --from=builder /app/cmd/dns-server .

RUN chmod +x ./dns-server

CMD ["./dns-server"]
