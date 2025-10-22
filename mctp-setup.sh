#!/bin/bash

mctp link serial ttyS1 &
sleep 1
echo 'Adding EID 9 as local address'
mctp addr add 9 dev mctpserial0
echo 'Adding route for EID 8 as remote address'
mctp route add 8 via mctpserial0
mctp link set mctpserial0 up
echo -e 'MCTP serial link is up\n'

