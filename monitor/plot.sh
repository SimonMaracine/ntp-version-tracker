#! /bin/bash

if [ "$1" = "" ]; then
    echo "Please provide an output directory"
    exit 1
fi

OUT_DIR="$1"

gnuplot -e "outdir='$OUT_DIR'" plot
