###################################
# STEP 1 build executable binary
###################################
FROM golang:1.27-alpine AS builder

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY *.go vendor go.mod go.sum ./
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o /app/enphase-exporter ./*.go

###################################
# STEP 2 build a small image
###################################
FROM scratch
# TODO: runs as root (uid 0) — scratch has no /etc/passwd so there's no user
# to switch to. Static binary needs no privileged port; worth a distroless
# nonroot base or an explicit numeric UID if this ever gets revisited.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/enphase-exporter /enphase-exporter
EXPOSE 9100
CMD ["/enphase-exporter"]
