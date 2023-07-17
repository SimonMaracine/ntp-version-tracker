#! /bin/sh

# This script works only on that particular router

# The output format should provide:
#     MEM  CPU
#     123  2
#     123  2
#     137  4
#     136  3

if [ "$1" = "" ]; then
    echo "Please provide a pid"
    exit 1
fi

OUT="out_monitor.txt"

echo "Starting to monitor; writing to $OUT"

top -b -d 1 | awk -v p="$1" '$1 == p {print $5, $7, $8}' > "$OUT"
