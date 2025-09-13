# Simple Makefile for CEP project

# Directories
SRCDIR := src
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# Target
TARGET := $(BIN_DIR)/test.exe

# Tools and flags
CC := gcc
CFLAGS := -g -Wall -D_DNU_SOURCE -D__STDC_NO_ATOMICS__ -fplan9-extensions \
          -I$(SRCDIR)/l0_kernel -I$(SRCDIR)/test
LDFLAGS :=

# Sources and objects (only cep_cell.* and tests)
SRC := $(SRCDIR)/l0_kernel/cep_cell.c \
       $(wildcard $(SRCDIR)/test/*.c)
OBJ := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))

.PHONY: all run debug clean

all: $(TARGET)

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

clean:
	rm -rf "$(BUILD_DIR)"
