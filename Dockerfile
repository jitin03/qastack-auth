FROM golang:1.16-alpine

RUN mkdir /app
ADD . /app
WORKDIR /app

RUN go build -o app main.go

#FROM alpine:latest AS production
COPY --from=builder /app .
CMD ["./app"]