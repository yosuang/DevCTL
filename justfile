set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

exe := if os() == "windows" { ".exe" } else { "" }
export CGO_CPPFLAGS := env("CGO_CPPFLAGS", env("CPPFLAGS", ""))
export CGO_CFLAGS := env("CGO_CFLAGS", env("CFLAGS", ""))
[private]
_cgo_ldflags_filtered := if os() == "windows" { "" } else { `printf '%s\n' ${LDFLAGS:-} | grep -E '^(-g$|-L|-l|-O)' | tr '\n' ' ' || true` }
export CGO_LDFLAGS := env("CGO_LDFLAGS", _cgo_ldflags_filtered)

[private]
default:
    @just --list

build: _build-script
    @./script/build{{ exe }} bin/devctl{{ exe }}

clean: _build-script
    @./script/build{{ exe }} clean

check:
    go mod tidy
    golangci-lint{{ exe }} fmt
    golangci-lint{{ exe }} run --fix

test:
    go test ./...

[private]
[unix]
_build-script:
    @GOOS= GOARCH= GOARM= GOFLAGS= CGO_ENABLED= go build -o script/build script/build.go

[private]
[windows]
_build-script:
    @go build -o script/build.exe script/build.go
