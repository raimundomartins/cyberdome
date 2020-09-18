#!/bin/sh

VOIDPTRDEF="$(echo "" | gcc -E -dD -xc - | grep SIZEOF_POINTER)"
if [ $? -ne 0 ]
then
    echo Failed to determine sizeof pointer
    exit 4
fi
VOIDPTRSIZE="$(echo "$VOIDPTRDEF" | cut -d' ' -f3)"
unset VOIDPTRDEF

MAX_STATIC=$(($VOIDPTRSIZE * 8))

if [ ! -e libproteins.so ] || [ proteins.c -nt libproteins.so ]; then
    fold_proteins.sh
    if [ $? -ne 0 ]; then
        echo "Error: Unable to fold proteins!"
        exit 3
    fi
fi

IN="$1"
OUT="${IN%.*}"

CFLAGS="\
    -pedantic\
    -Wall
    --warn-error\
    -nostdlib\
    -nostartfiles\
    -ffreestanding\
    -fno-stack-protector\
    -fno-asynchronous-unwind-tables\
    -fno-exceptions\
    -no-pie\
    -L. -lproteins"

case "${IN##*.}" in
    c|i)
        CC=gcc
        CFLAGS="$CFLAGS -std=c18"
        ;;
    cc|cp|cxx|cpp|CPP|c++|C|ii)
        CC=g++ 
        CFLAGS="$CFLAGS -std=c++17"
        ;;
    *)
        echo "Unsupported file extension"
        exit 5
        ;;
esac

echo Sequencing DNA... "(transpiling and checking)"
"$CC" "$IN" $CFLAGS -O0 -S -o "$OUT".S
if [ $? -ne 0 ]
then
    echo "Error: your DNA doesn't fold :("
    exit 1
fi

grep -n -A4 -B4 "^\s*syscall[^:]" "$OUT".S 2>/dev/null
if [ $? -eq 0 ]
then
    echo "Stop trying to cheat: no syscalls allowed!"
    exit 2
fi

echo Adding some codons and folding DNA... "(compiling)"
"$CC" start.S "$IN" $CFLAGS -Os -o "$OUT"
if [ $? -ne 0 ]
then
    echo "Error: the universe is broken :( (it's not your fault!)"
    exit 3
fi

section_size() {
    readelf -S "$OUT" \
    | grep -A1 '\[\s*[0-9]*\]' \
    | grep -A1 -e '\.'"$1" \
    | tail -1 \
    | awk '{print $1}' \
    | sed 's/^0*//'
}

BSS="$(section_size bss)"
DATA="$(section_size data)"
if [ $((${BSS:-0} + ${DATA:-0})) -gt $MAX_STATIC ]
then
    echo "Stop trying to cheat: data and bss sections combined can't be larger than $MAX_STATIC!"
    exit 2
fi

echo "Pruning DNA a bit... (stripping binary)"
strip -s -R .comment -R .gnu.hash -R .note.gnu.build-id -R .gnu.version -R .gnu.version_r "$OUT"

echo "Success: your DNA folded :)"

