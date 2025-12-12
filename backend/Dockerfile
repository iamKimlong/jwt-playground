FROM golang:1.21-alpine
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod ./
COPY . .
RUN go mod tidy
RUN go build -o main .
EXPOSE 8080
CMD ["./main"]
