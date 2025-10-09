# AST1060 mctp over serial echo example

A MCTP demo/test application that runs on the Aspeed AST1030/AST1060.

An echo task listens for incoming MCTP reqests with message type `1` and replies by echoing the payload.

EID is statically assigned to `8` by the echo task.

## Testing under Linux

Requirements:
- Linux with Kernel version 5.17 or later
 - `CONFIG_MCTP` = `y`
 - `CONFIG_MCTP_SERIAL` = `y` or `m`
- [MCTP userspace tools](https://github.com/CodeConstruct/mctp)
- Host test application (see [/test/test-mctp-request/](/test/test-mctp-request/))

The serial port of the AST1060 can be linked to a Linux MCTP protocol stack as shown in the test script ([`test-mctp.sh`](test-mctp.sh)).
The test script uses the QEMU Arm `ast1030-evb` board model.
A test application is then launched, to send a request over the Linux MCTP stack, waiting for the response.
The test application is located under [/test/test-mctp-request/](/test/test-mctp-request/) and needs to be build manually.

The provided script has to be run from the workspace/repository root.
