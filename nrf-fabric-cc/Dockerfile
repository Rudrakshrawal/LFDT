# FROM golang:1.21-alpine AS builder

# WORKDIR /app

# COPY go.mod go.sum ./
# RUN go mod download

# COPY . .

# # Build chaincode
# RUN CGO_ENABLED=0 GOOS=linux go build -o /chaincode ./chaincode/main.go

# # Build HTTP server
# RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./server/main.go

# FROM alpine:latest

# RUN apk --no-cache add ca-certificates

# WORKDIR /root/

# COPY --from=builder /chaincode .
# COPY --from=builder /server .

# # Default to chaincode mode
# CMD ["./chaincode"]



FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# COPY chaincode/ ./chaincode/
# COPY utils/ ./utils/
# COPY models/ ./models/
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /chaincode ./chaincode/

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /chaincode .
COPY nrf.key .

EXPOSE 9999

CMD ["./chaincode"]
