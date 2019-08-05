all: compile

clean:
	rm -rf build

compile: clean
	go test -v
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/inkfish-linux ./cmd/inkfish

