# =============================================================================
# HTTP Server Makefile
# =============================================================================

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2
CFLAGS += -I$(SRC_DIR)/include
LDFLAGS = -lpthread

# Detect OS
ifeq ($(OS),Windows_NT)
    TARGET = http_server.exe
    RM = del /Q /S
    RMDIR = rmdir /S /Q
    MKDIR = mkdir
    SEP = \\
else
    TARGET = http_server
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
    SEP = /
endif

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source files (recursive search)
SRCS = $(SRC_DIR)/main_new.c \
       $(SRC_DIR)/server/server.c \
       $(SRC_DIR)/http/http_parser.c \
       $(SRC_DIR)/handlers/handlers.c \
       $(SRC_DIR)/security/security.c \
       $(SRC_DIR)/compression/gzip.c \
       $(SRC_DIR)/utils/logging.c

# Object files
OBJS = $(BUILD_DIR)/main.o \
       $(BUILD_DIR)/server.o \
       $(BUILD_DIR)/http_parser.o \
       $(BUILD_DIR)/handlers.o \
       $(BUILD_DIR)/security.o \
       $(BUILD_DIR)/gzip.o \
       $(BUILD_DIR)/logging.o

# Legacy monolithic build
LEGACY_SRC = $(SRC_DIR)/main.c
LEGACY_OBJ = $(BUILD_DIR)/main_legacy.o

# =============================================================================
# TARGETS
# =============================================================================

.PHONY: all clean dirs legacy debug release run run-with-dir test help

# Default: build modular version
all: dirs $(BIN_DIR)/$(TARGET)
	@echo "Build complete: $(BIN_DIR)/$(TARGET)"

# Create build directories
dirs:
ifeq ($(OS),Windows_NT)
	@if not exist $(BUILD_DIR) $(MKDIR) $(BUILD_DIR)
	@if not exist $(BIN_DIR) $(MKDIR) $(BIN_DIR)
else
	@$(MKDIR) $(BUILD_DIR) $(BIN_DIR)
endif

# Link final executable
$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# =============================================================================
# COMPILATION RULES
# =============================================================================

$(BUILD_DIR)/main.o: $(SRC_DIR)/main_new.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/server.o: $(SRC_DIR)/server/server.c $(SRC_DIR)/server/server.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/http_parser.o: $(SRC_DIR)/http/http_parser.c $(SRC_DIR)/http/http_parser.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/handlers.o: $(SRC_DIR)/handlers/handlers.c $(SRC_DIR)/handlers/handlers.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/security.o: $(SRC_DIR)/security/security.c $(SRC_DIR)/security/security.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/gzip.o: $(SRC_DIR)/compression/gzip.c $(SRC_DIR)/compression/gzip.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/logging.o: $(SRC_DIR)/utils/logging.c $(SRC_DIR)/utils/logging.h
	$(CC) $(CFLAGS) -c $< -o $@

# =============================================================================
# LEGACY BUILD (single file)
# =============================================================================

legacy: dirs $(BIN_DIR)/http_server_legacy
	@echo "Legacy build complete: $(BIN_DIR)/http_server_legacy"

$(BIN_DIR)/http_server_legacy: $(LEGACY_OBJ)
	$(CC) $(LEGACY_OBJ) -o $@ $(LDFLAGS)

$(LEGACY_OBJ): $(LEGACY_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# =============================================================================
# BUILD VARIANTS
# =============================================================================

# Debug build with symbols
debug: CFLAGS += -g -O0 -DDEBUG
debug: all

# Release build with optimizations
release: CFLAGS += -O3 -DNDEBUG
release: all

# =============================================================================
# RUN TARGETS
# =============================================================================

run: all
	$(BIN_DIR)/$(TARGET)

run-with-dir: all
ifeq ($(OS),Windows_NT)
	@if not exist files $(MKDIR) files
else
	@$(MKDIR) files
endif
	$(BIN_DIR)/$(TARGET) --directory files

# =============================================================================
# CLEAN
# =============================================================================

clean:
ifeq ($(OS),Windows_NT)
	@if exist $(BUILD_DIR) $(RMDIR) $(BUILD_DIR)
	@if exist $(BIN_DIR) $(RMDIR) $(BIN_DIR)
else
	$(RMDIR) $(BUILD_DIR) $(BIN_DIR)
endif

# =============================================================================
# HELP
# =============================================================================

help:
	@echo "HTTP Server Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build modular server (default)"
	@echo "  legacy       - Build monolithic server (single main.c)"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build with optimizations"
	@echo "  run          - Build and run server"
	@echo "  run-with-dir - Build and run with --directory files"
	@echo "  clean        - Remove build artifacts"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Source Structure:"
	@echo "  src/main_new.c          - Entry point"
	@echo "  src/server/             - Server lifecycle"
	@echo "  src/http/               - HTTP parsing"
	@echo "  src/handlers/           - Request handlers"
	@echo "  src/security/           - Security functions"
	@echo "  src/compression/        - Gzip compression"
	@echo "  src/utils/              - Logging utilities"
	@echo "  src/include/            - Common headers"
