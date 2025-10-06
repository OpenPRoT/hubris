# AST1060 mctp over serial echo example

A MCTP demo/test application that runs on the Aspeed AST1030/AST1060.

An echo task listens for incoming MCTP reqests for message type `1` and replies by echoing the payload.

EID is statically assigned to `8`.

The serial port of the AST1060 can be linked to a Linux MCTP protocol stack as shown in the test script (`test-mctp-sh`).
The test script uses the QEMU Arm `ast1030-evb` board model.
An test application is then launched, to send a request over the Linux MCTP stack, waiting for the response.
The test application is located under [/test/test-mctp-request/](/test/test-mctp-request/) and needs to be build manually.
