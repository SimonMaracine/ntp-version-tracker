SRC_DIR = src
OUT_DIR = out
SOURCES = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
BIN = ntp_version_tracker

# Compiler flags
WARNINGS = -Wall -Wextra -pedantic
LIBS = -lpcap
ARGS = -std=c11 -D _GNU_SOURCE
# -D_POSIX_C_SOURCE=200809L

ifeq ($(BUILD_RELEASE), ON)
OPTIMIZATION = -O2
else
OPTIMIZATION = -O0
endif

.PHONY: all
all: ntp_version_tracker

# For router
ntp_version_tracker: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(OPTIMIZATION) $(ARGS) -static $(LIBS) -o $(OUT_DIR)/$(BIN)

# For any Linux machine
local_ntp_version_tracker: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(OPTIMIZATION) $(ARGS) $(LIBS) -o $(OUT_DIR)/local_$(BIN)

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

upload:
	scp $(OUT_DIR)/$(BIN) root@192.168.1.1:/tmp/$(BIN)
