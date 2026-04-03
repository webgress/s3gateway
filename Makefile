.PHONY: build clean test run

BINARY=bin/s3gateway
SRC=./cmd/s3gateway

build:
	go build -o $(BINARY) $(SRC)

clean:
	rm -rf bin/

test:
	go test ./... -race -v

vet:
	go vet ./...

run: build
	$(BINARY) -data-dir /tmp/s3gateway-data -credentials config/example-credentials.json
