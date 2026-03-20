set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

exe := if os() == "windows" { ".exe" } else { "" }

export CGO_CPPFLAGS := env_var_or_default("CGO_CPPFLAGS", env_var_or_default("CPPFLAGS", ""))
export CGO_CFLAGS := env_var_or_default("CGO_CFLAGS", env_var_or_default("CFLAGS", ""))
_cgo_ldflags_filtered := if os() == "windows" { "" } else { `printf '%s\n' ${LDFLAGS:-} | grep -E '^(-g$|-L|-l|-O)' | tr '\n' ' ' || true` }
export CGO_LDFLAGS := env_var_or_default("CGO_LDFLAGS", _cgo_ldflags_filtered)

[private]
default:
  @just --list

build: _build-script
    @./script/build{{exe}} bin/devctl{{exe}}

clean: _build-script
    @./script/build{{exe}} clean

lint:
    golangci-lint{{exe}} fmt && golangci-lint{{exe}} run --fix

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
