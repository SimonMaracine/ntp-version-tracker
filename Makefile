SRC_DIR = src
OUT_DIR = out
SOURCES = $(SRC_DIR)/*.c
BIN = ntp_version_tracker

WARNINGS = -Wall -Wextra -pedantic
LIBS = -lpcap
ARGS = -std=c11 -D _GNU_SOURCE
# -std=c11 -D_POSIX_C_SOURCE=200809L

.PHONY: all
all: sniffer

# For router
ntp_version_tracker: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(ARGS) -static $(LIBS) -o $(OUT_DIR)/$(BIN)

# For any Linux machine
local_ntp_version_tracker: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(ARGS) $(LIBS) -o $(OUT_DIR)/local_$(BIN)

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

upload:
	scp $(OUT_DIR)/$(BIN) root@192.168.1.1:/tmp/$(BIN)
