# sysrift — Static binary build targets
#
# Prerequisites:
#   x86_64 static:        Docker + crystallang/crystal:latest-musl
#   x86_64 static native: musl-gcc installed (apt install musl-tools)
#   arm64 static:         Docker + QEMU binfmt (sudo apt install qemu-user-static)
#   local:                crystal installed natively
#
# Usage:
#   make local          — build for current machine (dynamic, for testing)
#   make x86_64         — static x86_64 binary via Docker
#   make x86_64-native  — static x86_64 binary via native musl-gcc (no Docker)
#   make arm64          — static arm64 binary via Docker + QEMU
#   make all            — x86_64 + arm64
#   make strip-native   — strip native static binary (reduce size)
#   make strip-x86_64   — strip Docker static binary (reduce size)
#   make clean          — remove dist/

SRC      = sysrift.cr
BIN      = linaudit
DIST     = dist
FLAGS    = --release --no-debug
MUSL_IMG = crystallang/crystal:latest-musl

.PHONY: all local x86_64 x86_64-native arm64 strip-native strip-x86_64 clean check help

all: x86_64 arm64

## ── Local build (native arch, dynamically linked) ───────────
local: $(DIST)
	crystal build $(FLAGS) $(SRC) -o $(DIST)/$(BIN)_local
	@echo ""
	@echo "[ok] Built: $(DIST)/$(BIN)_local"
	@ls -lh $(DIST)/$(BIN)_local

## ── x86_64 static binary via Docker ────────────────────────
x86_64: $(DIST)
	docker run --rm \
		--platform linux/amd64 \
		-v "$(PWD):/src" \
		-w /src \
		$(MUSL_IMG) \
		crystal build --static $(FLAGS) $(SRC) -o $(DIST)/$(BIN)_x86_64
	@echo ""
	@echo "[ok] Built: $(DIST)/$(BIN)_x86_64"
	@ls -lh $(DIST)/$(BIN)_x86_64

## ── x86_64 static binary via native musl-gcc (no Docker) ───
## Requires: sudo apt install musl-tools
## Primary static build path — verified static output, no Docker needed
x86_64-native: $(DIST)
	crystal build --static $(FLAGS) \
		--link-flags "-static" \
		$(SRC) -o $(DIST)/$(BIN)_x86_64_native
	@echo ""
	@echo "[ok] Built: $(DIST)/$(BIN)_x86_64_native"
	@ls -lh $(DIST)/$(BIN)_x86_64_native
	@echo ""
	@echo "  Verify static: file $(DIST)/$(BIN)_x86_64_native"
	@echo "  Verify static: ldd  $(DIST)/$(BIN)_x86_64_native"

## ── arm64 static binary via Docker + QEMU ──────────────────
## Requires: sudo apt install qemu-user-static binfmt-support
##           docker run --privileged --rm tonistiigi/binfmt --install all
arm64: $(DIST)
	docker run --rm \
		--platform linux/arm64 \
		-v "$(PWD):/src" \
		-w /src \
		$(MUSL_IMG) \
		crystal build --static $(FLAGS) $(SRC) -o $(DIST)/$(BIN)_arm64
	@echo ""
	@echo "[ok] Built: $(DIST)/$(BIN)_arm64"
	@ls -lh $(DIST)/$(BIN)_arm64

## ── Strip binaries (remove debug symbols, reduce size) ──────
## Run after build. Preserves static linking, removes symbol table.
## Reduces binary size ~30-40%. Does not affect functionality.
## Note: string literals remain intact — not an obfuscation tool.
## Note: ldd returns exit code 1 for static binaries — this is correct.
strip-native:
	@test -f $(DIST)/$(BIN)_x86_64_native || \
		(echo "[!] Run 'make x86_64-native' first" && exit 1)
	strip $(DIST)/$(BIN)_x86_64_native
	@echo "[ok] Stripped: $(DIST)/$(BIN)_x86_64_native"
	@ls -lh $(DIST)/$(BIN)_x86_64_native
	@echo ""
	@file $(DIST)/$(BIN)_x86_64_native
	@ldd  $(DIST)/$(BIN)_x86_64_native || true

strip-x86_64:
	@test -f $(DIST)/$(BIN)_x86_64 || \
		(echo "[!] Run 'make x86_64' first" && exit 1)
	strip $(DIST)/$(BIN)_x86_64
	@echo "[ok] Stripped: $(DIST)/$(BIN)_x86_64"
	@ls -lh $(DIST)/$(BIN)_x86_64
	@echo ""
	@file $(DIST)/$(BIN)_x86_64
	@ldd  $(DIST)/$(BIN)_x86_64 || true

## ── Syntax check (no binary output) ────────────────────────
check:
	crystal build --no-codegen $(SRC)
	@echo "[ok] Syntax OK"

## ── Create dist dir ─────────────────────────────────────────
$(DIST):
	mkdir -p $(DIST)

## ── Clean ───────────────────────────────────────────────────
clean:
	rm -rf $(DIST)
	@echo "[ok] Cleaned"

## ── Help ────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make local          — native build (dynamic, dev/test)"
	@echo "  make x86_64         — static x86_64 via Docker musl"
	@echo "  make x86_64-native  — static x86_64 via native musl-gcc (no Docker)"
	@echo "  make arm64          — static arm64  via Docker musl + QEMU"
	@echo "  make all            — x86_64 + arm64"
	@echo "  make strip-native   — strip native static binary"
	@echo "  make strip-x86_64   — strip Docker static binary"
	@echo "  make check          — syntax check only"
	@echo "  make clean          — remove dist/"
	@echo ""
	@echo "  Recommended workflow:"
	@echo "    make x86_64-native   — build static binary"
	@echo "    make strip-native    — strip and verify"
	@echo ""
	@echo "  Drop to target:  scp dist/$(BIN)_x86_64_native user@target:/dev/shm/linaudit"
	@echo "  Run:             chmod +x /dev/shm/linaudit && /dev/shm/linaudit"
	@echo ""
	@echo "  Verify static build:"
	@echo "    file dist/$(BIN)_x86_64_native  →  'statically linked'"
	@echo "    ldd  dist/$(BIN)_x86_64_native  →  'not a dynamic executable'"
	@echo ""
