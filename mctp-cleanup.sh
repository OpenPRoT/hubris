#!/bin/bash

PID=`ps ax |grep "mctp link" | grep -v "grep" | sed -E 's/  ([0-9]*) .*/\1/'`

mctp link set mctpserial0 down
mctp route del 8 via mctpserial0
mctp addr del 9 dev mctpserial0

kill $PID
