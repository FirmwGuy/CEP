#!/usr/bin/make -f
# Fallback Makefile for CEP (no-internet builds)

# Directories
SRCDIR := ../src
THIRD_PARTY_DIR := $(SRCDIR)/third_party
# Use a separate build dir so accidental `make` does not clobber Meson builds
BUILD_DIR := ../build-make
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
DOCS_DIR := $(BUILD_DIR)/docs
DOXYFILE := $(DOCS_DIR)/Doxyfile
DOCS_HTML_INDEX := $(DOCS_DIR)/html/index.html

# Target
TARGET := $(BIN_DIR)/cep_tests

# Platform detection (used for flags/backends)
UNAME_S := $(shell uname -s 2>/dev/null)

# Tools and flags
CC ?= gcc
CFLAGS ?= -g -Wall -std=gnu11 -D_GNU_SOURCE -fplan9-extensions \
          -I$(SRCDIR)/l0_kernel -I$(SRCDIR)/l0_kernel/storage \
          -I$(SRCDIR)/l0_kernel/secdata \
          -I$(SRCDIR)/l1_coherence \
          -I$(SRCDIR)/l2_ecology \
          -I$(SRCDIR)/cps \
          -I$(SRCDIR)/enzymes \
          -I$(THIRD_PARTY_DIR)/blake3 \
          -I$(THIRD_PARTY_DIR)/munit \
          -I$(THIRD_PARTY_DIR)/libsodium/src/libsodium/include \
          -I$(THIRD_PARTY_DIR)/libsodium/src/libsodium/include/sodium \
          -I$(SRCDIR)/test
# Keep the fallback deterministic and portable.
CFLAGS += -DCEP_RV_DISABLED=1 \
          -DCEP_EXECUTOR_BACKEND_STUB=1 \
          -DCEP_LIBSODIUM_BUNDLED=1 \
          -DCONFIGURED=1 \
          -DDEV_MODE=0 \
          -DSODIUM_STATIC=1 \
          -DCEP_ZLIB_BUNDLED=1 \
          -DBLAKE3_NO_SSE2 \
          -DBLAKE3_NO_SSE41 \
          -DBLAKE3_NO_AVX2 \
          -DBLAKE3_NO_AVX512 \
          -DBLAKE3_USE_NEON=0

# Allow epoll hints when building on Linux so the portable backend can still
# advertise support for switching later.
ifeq ($(UNAME_S),Linux)
  CFLAGS += -DCEP_IO_REACTOR_HAS_EPOLL=1 \
            -DCEP_IO_REACTOR_BACKEND_DEFAULT_EPOLL=1
else
  CFLAGS += -DCEP_IO_REACTOR_BACKEND_DEFAULT_PORTABLE=1
endif

ifeq ($(OS),Windows_NT)
CFLAGS += -D__STDC_NO_ATOMICS__
endif
LDFLAGS :=

ifeq ($(UNAME_S),Linux)
  CFLAGS += -pthread
  LDFLAGS += -pthread -lm -ldl
else ifeq ($(UNAME_S),Darwin)
  LDFLAGS += -lm
endif

# Optional libzip support (set USE_LIBZIP=1 to enable)
USE_LIBZIP ?= 0
ifeq ($(USE_LIBZIP),1)
  LIBZIP_CFLAGS := $(shell pkg-config --cflags libzip 2>/dev/null)
  LIBZIP_LIBS := $(shell pkg-config --libs libzip 2>/dev/null)
  ifneq ($(strip $(LIBZIP_LIBS)),)
    CFLAGS += $(LIBZIP_CFLAGS) -DCEP_HAS_LIBZIP=1
    LDFLAGS += $(LIBZIP_LIBS)
    USE_LIBZIP := 1
  else
    $(warning libzip requested but not found; building without zip support)
    USE_LIBZIP := 0
  endif
endif

# Sources and objects (core kernel plus tests)
CORE_SRC := $(wildcard $(SRCDIR)/l0_kernel/*.c) \
            $(wildcard $(SRCDIR)/l0_kernel/secdata/*.c) \
            $(wildcard $(SRCDIR)/l0_kernel/stream/*.c) \
            $(wildcard $(SRCDIR)/enzymes/*.c) \
            $(wildcard $(SRCDIR)/cps/*.c) \
            $(wildcard $(SRCDIR)/l1_coherence/*.c) \
            $(wildcard $(SRCDIR)/l2_ecology/*.c)

ifeq ($(USE_LIBZIP),0)
  CORE_SRC := $(filter-out $(SRCDIR)/l0_kernel/stream/cep_stream_zip.c,$(CORE_SRC))
endif

# Third-party sources bundled for offline builds
BLAKE3_SRC := \
  $(THIRD_PARTY_DIR)/blake3/blake3.c \
  $(THIRD_PARTY_DIR)/blake3/blake3_dispatch.c \
  $(THIRD_PARTY_DIR)/blake3/blake3_portable.c

# Always rely on the portable implementations in fallback builds.

LIBSODIUM_SRC := \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_core/hchacha20/core_hchacha20.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/crypto_verify/verify.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/randombytes/randombytes.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c \
  $(THIRD_PARTY_DIR)/libsodium/src/libsodium/randombytes/internal/randombytes_internal_random.c \
  $(THIRD_PARTY_DIR)/libsodium_shims.c \
  $(THIRD_PARTY_DIR)/libsodium_runtime_stubs.c

ZLIB_SRC := $(wildcard $(THIRD_PARTY_DIR)/zlib/*.c)

# Collect test sources. The fallback bundle skips libzip/L2 fixtures; the Meson
# build still exercises everything.
TEST_SRC := $(shell find $(SRCDIR)/test -type f -name '*.c' 2>/dev/null)

ifeq ($(USE_LIBZIP),0)
  TEST_SRC := $(filter-out $(SRCDIR)/test/l0_kernel/test_stream_zip.c,$(TEST_SRC))
endif

# Combine
SRC := $(CORE_SRC) $(BLAKE3_SRC) $(LIBSODIUM_SRC) $(ZLIB_SRC) $(TEST_SRC)
OBJ := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))

DOCS_MAIN_MD := $(firstword $(foreach f,../docs/CEP.md ../docs/README.md ../docs/BUILD.md,$(if $(wildcard $(f)),$(abspath $(f)))))
DOCS_MD := $(shell find ../docs -type f -name '*.md' 2>/dev/null)
DOCS_DOT_BIN := $(shell which dot 2>/dev/null)
DOCS_DOT_PATH := $(dir $(DOCS_DOT_BIN))

CYGPATH := $(shell command -v cygpath 2>/dev/null)
native = $(if $(CYGPATH),$(shell cygpath -m $(1)),$(1))

DOCS_OUTPUT_NATIVE := $(call native,$(abspath $(DOCS_DIR)))
DOCS_SOURCE_ROOT_NATIVE := $(call native,$(abspath ..))
DOCS_MAIN_NATIVE := $(if $(DOCS_MAIN_MD),$(call native,$(DOCS_MAIN_MD)))
DOCS_DOT_PATH_NATIVE := $(if $(DOCS_DOT_BIN),$(call native,$(DOCS_DOT_PATH)))

.PHONY: all run integration debug valgrind docs clean help

all: $(TARGET)

help:
	@echo "CEP fallback Makefile (no internet / no Meson)."
	@echo "Build dir: $(BUILD_DIR)"
	@echo "Targets: all, run, debug, valgrind, docs, clean"

# Link
$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) -Wall -o "$@" $(OBJ) $(LDFLAGS)

# Compile: place objects under build/obj mirroring source tree
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c "$<" -o "$@"

# Convenience targets
run: $(TARGET)
	"$(TARGET)" --log-visible debug

integration: $(TARGET)
	"$(TARGET)" --no-fork --single /CEP/integration_poc/l0/integration

debug: $(TARGET)
	gdb -w --args "$(TARGET)" --log-visible debug

VALGRIND ?= valgrind
VALGRIND_FLAGS ?= --tool=memcheck --error-exitcode=1 --quiet

valgrind: $(TARGET)
	$(VALGRIND) $(VALGRIND_FLAGS) "$(TARGET)" --log-visible debug

docs: $(DOCS_HTML_INDEX)
	@echo "HTML docs ready at $(DOCS_HTML_INDEX)"

$(DOCS_HTML_INDEX): $(DOXYFILE) $(SRC) $(DOCS_MD)
	@mkdir -p $(DOCS_DIR)
	@command -v doxygen >/dev/null || { echo "doxygen not found"; exit 1; }
	@command -v dot >/dev/null || { echo "dot not found"; exit 1; }
	doxygen "$(DOXYFILE)"

$(DOXYFILE): ../docs/Doxyfile.in
	@mkdir -p $(DOCS_DIR)
	sed \
		-e 's|@PROJECT_NAME@|CEP|g' \
		-e 's|@PROJECT_VERSION@|0.1.0|g' \
		-e 's|@OUTPUT_DIRECTORY@|$(DOCS_OUTPUT_NATIVE)|g' \
		-e 's|@SOURCE_ROOT@|$(DOCS_SOURCE_ROOT_NATIVE)|g' \
		-e 's|@STRIP_FROM_PATH@|$(DOCS_SOURCE_ROOT_NATIVE)|g' \
		-e 's|@DOT_PATH@|$(DOCS_DOT_PATH_NATIVE)|g' \
		-e 's|@MAIN_PAGE@|$(DOCS_MAIN_NATIVE)|g' \
		 $< > $@

clean:
	rm -rf "$(BUILD_DIR)"
