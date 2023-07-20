SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

SOURCES := $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/**/*.c)
HEADERS := $(wildcard $(SRC_DIR)/*.h $(SRC_DIR)/**/*.h)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TARGET := ntp_version_tracker

# Compiler flags
WARNINGS := -Wall -Wextra -pedantic
LIBS := -lpcap -lpthread -ljansson
FLAGS := -std=c11 -D _GNU_SOURCE
DEFINITIONS ?=

# Option for compiling with optimization
BUILD_RELEASE ?=

ifeq ($(BUILD_RELEASE), 1)
FLAGS += -O2
DEFINITIONS += -DNDEBUG
else
FLAGS += -O0
endif

.PHONY: all clean

all: $(TARGET)

# For router; run setup.sh before
$(TARGET): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $(BIN_DIR)/$@ $(FLAGS) -static $(LIBS)

# For any Linux machine
local_$(TARGET): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $(BIN_DIR)/$@ $(FLAGS) $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) -c $< -o $@ $(WARNINGS) $(DEFINITIONS) $(FLAGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

upload:
	scp $(BIN_DIR)/$(TARGET) root@192.168.1.1:/tmp/$(TARGET)
