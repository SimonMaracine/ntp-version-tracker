SRC_DIR = src
OUT_DIR = out
SOURCES = $(SRC_DIR)/*.c

WARNINGS = -Wall -Wextra -pedantic
LIBS = -lpcap
ARGS = -std=c11 -D _GNU_SOURCE
# -std=c11 -D_POSIX_C_SOURCE=200809L

.PHONY: all
all: sniffer

sniffer: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(ARGS) -static $(LIBS) -o $(OUT_DIR)/sniffer

sniffer_local: $(SOURCES)
	@mkdir -p $(OUT_DIR)
	$(CC) $(SOURCES) $(WARNINGS) $(ARGS) $(LIBS) -o $(OUT_DIR)/sniffer_local

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

upload:
	scp $(OUT_DIR)/sniffer root@192.168.1.1:/tmp/sniffer
