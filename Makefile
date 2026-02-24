SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo
RUSTUP ?= rustup
DIST_DIR ?= dist

MACOS_ARM64_TARGET ?= aarch64-apple-darwin
MACOS_X86_64_TARGET ?= x86_64-apple-darwin
LINUX_X86_64_TARGET ?= x86_64-unknown-linux-gnu
LINUX_ARM64_TARGET ?= aarch64-unknown-linux-gnu
LINUX_ARM64_LINKER ?= aarch64-linux-gnu-gcc

SOTH_UNIVERSAL := $(DIST_DIR)/soth-darwin-universal2
SOTH_OPS_UNIVERSAL := $(DIST_DIR)/soth-ops-darwin-universal2
SOTH_LINUX_AMD64 := $(DIST_DIR)/soth-linux-amd64
SOTH_LINUX_ARM64 := $(DIST_DIR)/soth-linux-arm64
SOTH_OPS_LINUX_AMD64 := $(DIST_DIR)/soth-ops-linux-amd64
SOTH_OPS_LINUX_ARM64 := $(DIST_DIR)/soth-ops-linux-arm64

.PHONY: help \
	macos-universal \
	macos-universal-soth \
	macos-universal-soth-ops \
	macos-universal-verify \
	macos-universal-prereqs \
	macos-universal-targets \
	linux-binaries \
	linux-binaries-soth \
	linux-binaries-soth-ops \
	linux-binaries-verify \
	linux-binaries-prereqs \
	linux-binaries-targets \
	clean-dist

help:
	@echo "Targets:"
	@echo "  make macos-universal         Build Universal 2 macOS binaries for soth + soth-ops"
	@echo "  make macos-universal-soth    Build Universal 2 macOS binary for soth"
	@echo "  make macos-universal-soth-ops Build Universal 2 macOS binary for soth-ops"
	@echo "  make macos-universal-verify  Verify universal binaries in $(DIST_DIR)"
	@echo "  make linux-binaries          Build split Linux binaries (amd64 + arm64) for soth + soth-ops"
	@echo "  make linux-binaries-soth     Build split Linux binaries for soth"
	@echo "  make linux-binaries-soth-ops Build split Linux binaries for soth-ops"
	@echo "  make linux-binaries-verify   Verify Linux split binaries in $(DIST_DIR)"
	@echo "  make clean-dist              Remove $(DIST_DIR) outputs"

macos-universal-prereqs:
	@if [[ "$$(uname -s)" != "Darwin" ]]; then \
		echo "error: macos-universal targets must run on macOS"; \
		exit 1; \
	fi
	@command -v lipo >/dev/null 2>&1 || { echo "error: missing required tool 'lipo'"; exit 1; }
	@command -v shasum >/dev/null 2>&1 || { echo "error: missing required tool 'shasum'"; exit 1; }
	@command -v file >/dev/null 2>&1 || { echo "error: missing required tool 'file'"; exit 1; }

macos-universal-targets:
	@$(RUSTUP) target add $(MACOS_ARM64_TARGET) $(MACOS_X86_64_TARGET)

$(SOTH_UNIVERSAL): macos-universal-prereqs macos-universal-targets
	@mkdir -p "$(DIST_DIR)"
	$(CARGO) build -p soth-cli --bin soth --release --target "$(MACOS_ARM64_TARGET)"
	$(CARGO) build -p soth-cli --bin soth --release --target "$(MACOS_X86_64_TARGET)"
	lipo -create \
		"target/$(MACOS_ARM64_TARGET)/release/soth" \
		"target/$(MACOS_X86_64_TARGET)/release/soth" \
		-output "$(SOTH_UNIVERSAL)"
	chmod +x "$(SOTH_UNIVERSAL)"
	shasum -a 256 "$(SOTH_UNIVERSAL)" > "$(SOTH_UNIVERSAL).sha256"

$(SOTH_OPS_UNIVERSAL): macos-universal-prereqs macos-universal-targets
	@mkdir -p "$(DIST_DIR)"
	$(CARGO) build -p soth-cli --bin soth-ops --release --no-default-features --features ops --target "$(MACOS_ARM64_TARGET)"
	$(CARGO) build -p soth-cli --bin soth-ops --release --no-default-features --features ops --target "$(MACOS_X86_64_TARGET)"
	lipo -create \
		"target/$(MACOS_ARM64_TARGET)/release/soth-ops" \
		"target/$(MACOS_X86_64_TARGET)/release/soth-ops" \
		-output "$(SOTH_OPS_UNIVERSAL)"
	chmod +x "$(SOTH_OPS_UNIVERSAL)"
	shasum -a 256 "$(SOTH_OPS_UNIVERSAL)" > "$(SOTH_OPS_UNIVERSAL).sha256"

macos-universal-soth: $(SOTH_UNIVERSAL)
	@echo "Built $(SOTH_UNIVERSAL)"

macos-universal-soth-ops: $(SOTH_OPS_UNIVERSAL)
	@echo "Built $(SOTH_OPS_UNIVERSAL)"

macos-universal: $(SOTH_UNIVERSAL) $(SOTH_OPS_UNIVERSAL)
	@$(MAKE) macos-universal-verify

macos-universal-verify: macos-universal-prereqs
	@test -f "$(SOTH_UNIVERSAL)" || { echo "error: missing $(SOTH_UNIVERSAL)"; exit 1; }
	@test -f "$(SOTH_OPS_UNIVERSAL)" || { echo "error: missing $(SOTH_OPS_UNIVERSAL)"; exit 1; }
	file "$(SOTH_UNIVERSAL)" "$(SOTH_OPS_UNIVERSAL)"
	lipo -archs "$(SOTH_UNIVERSAL)"
	lipo -archs "$(SOTH_OPS_UNIVERSAL)"
	@echo "Checksums:"
	@cat "$(SOTH_UNIVERSAL).sha256"
	@cat "$(SOTH_OPS_UNIVERSAL).sha256"

linux-binaries-prereqs:
	@command -v shasum >/dev/null 2>&1 || { echo "error: missing required tool 'shasum'"; exit 1; }
	@command -v file >/dev/null 2>&1 || { echo "error: missing required tool 'file'"; exit 1; }

linux-binaries-targets:
	@$(RUSTUP) target add $(LINUX_X86_64_TARGET) $(LINUX_ARM64_TARGET)

$(SOTH_LINUX_AMD64): linux-binaries-prereqs linux-binaries-targets
	@mkdir -p "$(DIST_DIR)"
	$(CARGO) build -p soth-cli --bin soth --release --target "$(LINUX_X86_64_TARGET)"
	cp "target/$(LINUX_X86_64_TARGET)/release/soth" "$(SOTH_LINUX_AMD64)"
	chmod +x "$(SOTH_LINUX_AMD64)"
	shasum -a 256 "$(SOTH_LINUX_AMD64)" > "$(SOTH_LINUX_AMD64).sha256"

$(SOTH_LINUX_ARM64): linux-binaries-prereqs linux-binaries-targets
	@mkdir -p "$(DIST_DIR)"
	@command -v "$(LINUX_ARM64_LINKER)" >/dev/null 2>&1 || { \
		echo "error: missing required linker '$(LINUX_ARM64_LINKER)' for $(LINUX_ARM64_TARGET)"; \
		echo "hint: on Ubuntu/Debian install gcc-aarch64-linux-gnu"; \
		exit 1; \
	}
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$(LINUX_ARM64_LINKER)" \
		$(CARGO) build -p soth-cli --bin soth --release --target "$(LINUX_ARM64_TARGET)"
	cp "target/$(LINUX_ARM64_TARGET)/release/soth" "$(SOTH_LINUX_ARM64)"
	chmod +x "$(SOTH_LINUX_ARM64)"
	shasum -a 256 "$(SOTH_LINUX_ARM64)" > "$(SOTH_LINUX_ARM64).sha256"

$(SOTH_OPS_LINUX_AMD64): linux-binaries-prereqs linux-binaries-targets
	@mkdir -p "$(DIST_DIR)"
	$(CARGO) build -p soth-cli --bin soth-ops --release --no-default-features --features ops --target "$(LINUX_X86_64_TARGET)"
	cp "target/$(LINUX_X86_64_TARGET)/release/soth-ops" "$(SOTH_OPS_LINUX_AMD64)"
	chmod +x "$(SOTH_OPS_LINUX_AMD64)"
	shasum -a 256 "$(SOTH_OPS_LINUX_AMD64)" > "$(SOTH_OPS_LINUX_AMD64).sha256"

$(SOTH_OPS_LINUX_ARM64): linux-binaries-prereqs linux-binaries-targets
	@mkdir -p "$(DIST_DIR)"
	@command -v "$(LINUX_ARM64_LINKER)" >/dev/null 2>&1 || { \
		echo "error: missing required linker '$(LINUX_ARM64_LINKER)' for $(LINUX_ARM64_TARGET)"; \
		echo "hint: on Ubuntu/Debian install gcc-aarch64-linux-gnu"; \
		exit 1; \
	}
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$(LINUX_ARM64_LINKER)" \
		$(CARGO) build -p soth-cli --bin soth-ops --release --no-default-features --features ops --target "$(LINUX_ARM64_TARGET)"
	cp "target/$(LINUX_ARM64_TARGET)/release/soth-ops" "$(SOTH_OPS_LINUX_ARM64)"
	chmod +x "$(SOTH_OPS_LINUX_ARM64)"
	shasum -a 256 "$(SOTH_OPS_LINUX_ARM64)" > "$(SOTH_OPS_LINUX_ARM64).sha256"

linux-binaries-soth: $(SOTH_LINUX_AMD64) $(SOTH_LINUX_ARM64)
	@echo "Built $(SOTH_LINUX_AMD64)"
	@echo "Built $(SOTH_LINUX_ARM64)"

linux-binaries-soth-ops: $(SOTH_OPS_LINUX_AMD64) $(SOTH_OPS_LINUX_ARM64)
	@echo "Built $(SOTH_OPS_LINUX_AMD64)"
	@echo "Built $(SOTH_OPS_LINUX_ARM64)"

linux-binaries: $(SOTH_LINUX_AMD64) $(SOTH_LINUX_ARM64) $(SOTH_OPS_LINUX_AMD64) $(SOTH_OPS_LINUX_ARM64)
	@$(MAKE) linux-binaries-verify

linux-binaries-verify: linux-binaries-prereqs
	@test -f "$(SOTH_LINUX_AMD64)" || { echo "error: missing $(SOTH_LINUX_AMD64)"; exit 1; }
	@test -f "$(SOTH_LINUX_ARM64)" || { echo "error: missing $(SOTH_LINUX_ARM64)"; exit 1; }
	@test -f "$(SOTH_OPS_LINUX_AMD64)" || { echo "error: missing $(SOTH_OPS_LINUX_AMD64)"; exit 1; }
	@test -f "$(SOTH_OPS_LINUX_ARM64)" || { echo "error: missing $(SOTH_OPS_LINUX_ARM64)"; exit 1; }
	file "$(SOTH_LINUX_AMD64)" "$(SOTH_LINUX_ARM64)" "$(SOTH_OPS_LINUX_AMD64)" "$(SOTH_OPS_LINUX_ARM64)"
	@echo "Checksums:"
	@cat "$(SOTH_LINUX_AMD64).sha256"
	@cat "$(SOTH_LINUX_ARM64).sha256"
	@cat "$(SOTH_OPS_LINUX_AMD64).sha256"
	@cat "$(SOTH_OPS_LINUX_ARM64).sha256"

clean-dist:
	rm -rf "$(DIST_DIR)"
