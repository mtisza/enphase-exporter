###################################
# STEP 1 build executable binary
###################################
FROM golang:1.23-alpine AS builder

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY *.go vendor go.mod go.sum ./
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/enphase-exporter ./*.go

###################################
# STEP 2 build a small image
###################################
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/enphase-exporter /enphase-exporter
EXPOSE 9100
CMD ["/enphase-exporter"]
