#!/usr/bin/make -f
# Fallback Makefile for CEP (no-internet builds)

# Directories
SRCDIR := ../src
# Use a separate build dir so accidental `make` does not clobber Meson builds
BUILD_DIR := ../build-make
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
DOCS_DIR := $(BUILD_DIR)/docs
DOXYFILE := $(DOCS_DIR)/Doxyfile
DOCS_HTML_INDEX := $(DOCS_DIR)/html/index.html

# Target
TARGET := $(BIN_DIR)/cep_tests

# Tools and flags
CC ?= gcc
CFLAGS ?= -g -Wall -D_GNU_SOURCE -fplan9-extensions \
          -I$(SRCDIR)/l0_kernel -I$(SRCDIR)/l0_kernel/storage \
          -I$(SRCDIR)/l1_bond \
          -I$(SRCDIR)/test
ifeq ($(OS),Windows_NT)
CFLAGS += -D__STDC_NO_ATOMICS__
endif
LDFLAGS :=

# Sources and objects (core kernel plus tests)
SRC := $(SRCDIR)/l0_kernel/cep_cell.c \
       $(SRCDIR)/l0_kernel/cep_cell_stream.c \
       $(SRCDIR)/l0_kernel/cep_cell_system.c \
       $(SRCDIR)/l0_kernel/cep_enzyme.c \
       $(SRCDIR)/l0_kernel/cep_enzyme_bindings.c \
       $(SRCDIR)/l0_kernel/cep_heartbeat.c \
       $(SRCDIR)/l0_kernel/cep_heartbeat_queue.c \
       $(SRCDIR)/l0_kernel/cep_namepool.c \
       $(SRCDIR)/l0_kernel/cep_serialization.c \
       $(SRCDIR)/l1_bond/cep_bond.c \
       $(SRCDIR)/l0_kernel/stream/cep_stream_effects.c \
       $(SRCDIR)/l0_kernel/stream/cep_stream_stdio.c \
       $(wildcard $(SRCDIR)/test/*.c) \
       $(wildcard $(SRCDIR)/test/*/*.c)
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

.PHONY: all run debug docs clean help

all: $(TARGET)

help:
	@echo "CEP fallback Makefile (no internet / no Meson)."
	@echo "Build dir: $(BUILD_DIR)"
	@echo "Targets: all, run, debug, docs, clean"

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

debug: $(TARGET)
	gdb -w --args "$(TARGET)" --log-visible debug

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
