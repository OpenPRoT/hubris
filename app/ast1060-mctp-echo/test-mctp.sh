#!/bin/bash

# Run from the workspace root

set -e
trap "exit" INT TERM
trap "kill 0; rm ttyS1" EXIT

# Serial transport driver has to be loaded when configured as module
# (as tested with Fedora 42, kernel 6.16)
sudo modprobe mctp-serial

# Load the image into qemu and connect the serial to a chardev (symlinked to ttyS1)
qemu-system-arm -M ast1030-evb -nographic -chardev pty,id=char0,path=ttyS1 -serial chardev:char0 -kernel ./target/ast1060-mctp-echo/dist/default/final.bin &
sleep 1

echo -e '\n\nSetting up MCTP serial link'
sudo mctp link serial ttyS1 &
sleep 1
echo 'Adding EID 9 as local address'
sudo mctp addr add 9 dev mctpserial0
echo 'Adding route for EID 8 as remote address'
sudo mctp route add 8 via mctpserial0
sudo mctp link set mctpserial0 up
echo -e 'MCTP serial link is up\n'


echo -e 'Sending MCTP request...'
sudo ./target/debug/test-mctp-request

