.PHONY: dev clean

# Build the local devctl binary.
dev:
	./build/dev.sh

# Remove build artifacts.
clean:
	go run ./script/build.go clean
