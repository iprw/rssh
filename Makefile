BINARY   := rssh
GOFLAGS  := -trimpath
LDFLAGS  := -s -w

TARGETS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64

RELEASE_DIR := dist

.PHONY: build test clean release

build:
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/rssh
	@command -v upx && upx -9 $(BINARY) || true

test:
	go test -race -v ./...

# release cross-compiles the binary for all target platforms.
# Outputs are written to dist/rssh-<GOOS>-<GOARCH>.
release:
	@mkdir -p $(RELEASE_DIR)
	@$(foreach target,$(TARGETS), \
		$(eval GOOS   := $(word 1,$(subst /, ,$(target)))) \
		$(eval GOARCH := $(word 2,$(subst /, ,$(target)))) \
		echo "Building $(GOOS)/$(GOARCH)..." && \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) \
			-ldflags="$(LDFLAGS)" \
			-o $(RELEASE_DIR)/$(BINARY)-$(GOOS)-$(GOARCH) \
			./cmd/rssh && \
	) echo "Release builds complete. Artifacts in $(RELEASE_DIR)/."

clean:
	rm -f $(BINARY)
	rm -rf $(RELEASE_DIR)
