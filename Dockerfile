# syntax=docker/dockerfile:1

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /syncvaultd ./cmd/syncvaultd

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /
COPY --from=build /syncvaultd /syncvaultd
# PocketBase defaults to port 8090
EXPOSE 8090
# Data directory for PocketBase SQLite database (matches Fly.io mount at /data)
VOLUME ["/data"]
ENTRYPOINT ["/syncvaultd", "serve", "--http=0.0.0.0:8090", "--dir=/data"]
