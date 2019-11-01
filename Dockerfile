FROM golang:latest

WORKDIR /app
COPY . .

RUN go get github.com/Binject/go-donut/ && go get github.com/akamensky/argparse

RUN GOOS=linux GOARCH=amd64 go build -o goDonut .
ENTRYPOINT [ "/bin/bash" ]
