#!/bin/bash

NAME=dome/proteins
IN="$NAME".c
OUTH="$NAME".h
OUTL=lib"$NAME".so

wrap_in_extern_c() {
    echo "#ifdef __cplusplus\n\
extern \"C\" {\n\
#endif\n\
$1\n\
#ifdef __cplusplus\n\
}\n\
#endif"
}

map_export() {
    sed \
-e "s|\(.*\)\s*//\s*\<EXPORT\>\s*\<IF\>\s*\(.*\)|\
$(wrap_in_extern_c "#ifdef \2\n\1\n#endif")|" \
-e "s|\(.*\)\s*//\s*\<EXPORT\>|$(wrap_in_extern_c "\1")|"
}

map_all() {
    echo "$1" | map_export
}

filter() {
    BEGUN_SH=
    while IFS= read LINE; do
        if [[ -n "$BEGUN_SH" ]]; then
            if [[ "$LINE" =~ ^\ *//\ *"END SH" ]]; then
                BEGUN_SH=
            else
                map_all "$LINE" | eval $BEGUN_SH
            fi
        elif [[ "$LINE" =~ ^\ *//\ *"BEGIN SH: " ]]; then
            BEGUN_SH="$(echo "$LINE" | sed 's|^\s*//\s*BEGIN SH: ||')"
        else
            map_all "$LINE"
        fi
    done
}

# TODO: support cpp in the second gcc
gcc -DHEADER_ONLY -E -C -P "$IN" | filter | gcc -E -P -dD -fpreprocessed -x c - > "$OUTH"

gcc -shared -fPIC "$IN" -o "$OUTL"
