#!/bin/sh

i=0
while [ "$i" -lt 1000 ]; do
    cat /tmp/temp1 >/dev/null 2>&1
    cat /tmp/temp2 >/dev/null 2>&1
    cat /tmp/temp3 >/dev/null 2>&1
    cat /tmp/temp4 >/dev/null 2>&1
    cat /tmp/temp5 >/dev/null 2>&1
    cat /tmp/temp6 >/dev/null 2>&1
    cat /tmp/temp7 >/dev/null 2>&1
    cat /tmp/temp8 >/dev/null 2>&1
    cat /tmp/temp9 >/dev/null 2>&1
    cat /tmp/temp10 >/dev/null 2>&1
    i=$((i + 1))
done
