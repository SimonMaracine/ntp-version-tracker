SOURCES = main.c
OUT = out

.PHONY: all
all: sniffer

sniffer: $(SOURCES)
	@mkdir -p $(OUT)
	$(CC) $(SOURCES) -Wall -Wextra -pedantic -static -lpcap -o $(OUT)/sniffer

# -std=c11 -D_POSIX_C_SOURCE=200809L

sniffer_local: $(SOURCES)
	@mkdir -p $(OUT)
	$(CC) $(SOURCES) -Wall -Wextra -pedantic -lpcap -o $(OUT)/sniffer_local

.PHONY: clean
clean:
	rm -rf $(OUT)

upload:
	scp $(OUT)/sniffer root@192.168.1.1:/tmp/sniffer
