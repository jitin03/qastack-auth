FROM golang:alpine AS builder



# This will download all certificates (ca-certificates) and builds it in a
# single file under /etc/ssl/certs/ca-certificates.crt (update-ca-certificates)
# I also add git so that we can download with `go mod download` and
# tzdata to configure timezone in final image
RUN apk --update add --no-cache ca-certificates openssl git tzdata && \
update-ca-certificates
# Set necessary environmet variables needed for our image
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    DB_USER=postgres \
    DB_PASSWD=Home@302017 \
    DB_ADDR=3.229.43.168 \
    DB_PORT=5432 \
    DB_NAME=postgres


# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .



# Build the application
RUN go build -o main .

# Move to /dist directory as the place for resulting binary folder
WORKDIR /dist

# Copy binary from build to main folder
RUN cp /build/main .

############################
# STEP 2 build a small image
############################
FROM scratch

COPY --from=builder /dist/main /
#COPY ./database/data.json /database/data.json

# This line will copy all certificates to final image
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8090
# Command to run the executable
ENTRYPOINT ["/main"]
