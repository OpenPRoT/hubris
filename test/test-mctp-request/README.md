# MCTP request/echo test application

Test application that sends a "Hello, World!" request over the Linux MCTP protocol stack.
The message is send to environment variables `REMOTE_EID` and message type `MSG_TYPE`.
The remote EID defaults to `8` and the message type to `1`, if unset or invalid.

A check is performed that the response matches the request payload.
A timeout will occur after a fixed time of 5 seconds.
