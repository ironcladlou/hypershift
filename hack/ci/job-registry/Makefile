.PHONY: build clean fmt

build: fmt
	mkdir -p bin
	go build -o bin/job-registry .

fmt:
	gofmt -w main.go

clean:
	rm -f bin/job-registry
