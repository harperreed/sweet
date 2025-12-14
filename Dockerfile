# syntax=docker/dockerfile:1

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /syncvaultd ./cmd/syncvaultd

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /
COPY --from=build /syncvaultd /syncvaultd
EXPOSE 8080
ENTRYPOINT ["/syncvaultd"]
