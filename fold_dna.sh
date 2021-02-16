#!/bin/sh

calc_ptr_size() {
    local VOIDPTRDEF="$(echo "" | gcc -E -dD -xc - 2>/dev/null | grep SIZEOF_POINTER)"
    if [ $? -ne 0 ]
    then
        echo Failed to determine sizeof pointer
        exit 4
    fi
    VOIDPTRSIZE="$(echo "$VOIDPTRDEF" | cut -d' ' -f3)"
}

calc_ptr_size
MAX_STATIC=$(($VOIDPTRSIZE * 8))

IN="$1"
OUT="build/${IN%.*}"

debug_mode() {
    case "$DEBUG" in
        y|Y|yes|Yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

verbose_mode() {
    case "$VERBOSE" in
        n|N|no|No|NO) return 1 ;;
        *) return 0 ;;
    esac
}

call() {
    verbose_mode && echo "$@"
    "$@"
}

#    -pedantic\
#    --warn-error\
CFLAGS="\
    -Wall
    -nostdlib\
    -nostartfiles\
    -static\
    -ffreestanding\
    -fno-stack-protector\
    -fno-asynchronous-unwind-tables\
    -fno-exceptions\
    -I /usr/include\
    -no-pie"
#    -L. -lproteins"

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

if debug_mode; then
    CFLAGS="$CFLAGS -g"
fi

echo "Synthetizing aminoacids... (compiling to object code)"
call $CC "$IN" $CFLAGS -Os -c -o "$OUT.o"
if [ $? -ne 0 ]; then
    echo "Error: your DNA is deffective"
    exit 3
fi
if nm "$OUT.o" | grep _enforce_physics_; then
    echo "Stop trying to cheat: _enforce_physics_ is a reserved symbol!"
    exit 2
fi

section_size() {
    readelf -S "$OUT.o" \
    | grep -A1 '\[\s*[0-9]*\]' \
    | grep -A1 -e '\.'"$1" \
    | tail -1 \
    | awk '{print $1}' \
    | sed 's/^[^1-9]*\([0-9]\+\)/\1/' #'s/^0*//'
}

if [ $(($(section_size bss) + $(section_size data))) -gt $MAX_STATIC ]; then
    echo "Stop trying to cheat: data and bss sections combined can't be larger than $MAX_STATIC!"
    exit 2
fi

#call $CC dome/physics.c $CFLAGS -Os -S -o $OUT.S

echo "Adding some codons and folding DNA... (injecting startup code and linking)"
call $CC start.S dome/physics.c "$OUT.o" $CFLAGS -Os -o $OUT
if [ $? -ne 0 ]; then
    echo "Error: the universe is broken :( (it's not your fault!)"
    exit 3
fi

if ! debug_mode; then
    echo "Pruning DNA... (stripping binary)"
    strip -s -R .comment -R .gnu.hash -R .note.gnu.build-id -R .gnu.version \
        -R .gnu.version_r "${OUT}"
fi
echo "Success: your DNA folded :)"

make_asm_check_syscalls() { # Unused
    echo Sequencing DNA... "(transpiling and checking)"
    "$CC" "$IN" $CFLAGS -O0 -S -o "$OUT".S
    if [ $? -ne 0 ]; then
        echo "Error: your DNA doesn't fold :("
        exit 1
    fi

    grep -n -A4 -B4 "^\s*syscall[^:]" "$OUT".S 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Stop trying to cheat: no syscalls allowed!"
        exit 2
    fi
}

