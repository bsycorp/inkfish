all: compile

clean:
	rm -rf build

compile: clean
	go test -v
	sh -c 'export GOOS=darwin; export GOARCH=amd64; go build -o build/inkfish-darwin ./cmd/inkfish'
	sh -c 'export GOOS=linux; export GOARCH=amd64; go build -o build/inkfish-linux ./cmd/inkfish'

