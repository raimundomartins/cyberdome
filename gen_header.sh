#!/bin/bash

IN=polynucleotides.c
OUT=polynucleotides.h

filter() {
    BEGUN_EXPORT_H=
    BEGUN_SH=
    while IFS= read LINE; do
        if [[ -z "$BEGUN_EXPORT_H" ]]; then
            if [[ "$LINE" =~ ^\ *//\ *" -- BEGIN EXPORT H --"$ ]]; then
                BEGUN_EXPORT_H=1
            fi
        else
            if [[ "$LINE" =~ ^\ *//\ *" -- END EXPORT H --"$ ]]; then
                BEGUN_EXPORT_H=
            elif [[ -n "$BEGUN_SH" ]]; then
                if [[ "$LINE" =~ ^\ *//\ *"END SH" ]]; then
                    BEGUN_SH=
                else
                    echo "$LINE" | eval $BEGUN_SH
                fi
            elif [[ "$LINE" =~ ^\ *//\ *"BEGIN SH: " ]]; then
                BEGUN_SH="$(echo "$LINE" | sed 's|^\s*//\s*BEGIN SH: ||')"
            else
                echo "$LINE"
            fi
        fi
    done

    #L=( $(grep -n '// -- \(BEGIN\|END\) '"$1"' --' | cut -d':' -f1 | tr '\n' ' ') )
    #BEGIN=${L[0]}
    #END=${L[1]}
    #unset L
    #head -n $(($END-1)) | tail -n -$(($END-$BEGIN-1))
}

# TODO: support cpp in the second gcc
gcc -E -C -P "$IN" | filter | gcc -E -P -dD -fpreprocessed -x c - > "$OUT"
