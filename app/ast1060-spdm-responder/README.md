# AST1060 SPDM Responder Application

This application implements an SPDM (Security Protocol and Data Model) responder that communicates over MCTP transport via UART. The application consists of:

- **MCTP Server Task**: Handles MCTP protocol over UART/serial transport
- **SPDM Responder Task**: Processes SPDM messages received via MCTP
- Standard system tasks (jefe, idle)

## Building

```bash
cargo xtask dist app/ast1060-spdm-responder/app.toml
```

## Running in QEMU

Start QEMU with debugging enabled:
```bash
./run-qemu.sh ast1060-spdm-responder
```

Connect GDB for debugging (in another terminal):
```bash
./run-gdb.sh ast1060-spdm-responder
```

## Testing

The SPDM responder listens for SPDM messages on:
- **MCTP Message Type**: 5 (SPDM)
- **Endpoint ID**: 42
- **Transport**: UART/Serial

To test the responder, you need an **external SPDM client** that can:
1. Connect to the UART interface
2. Send MCTP-wrapped SPDM messages
3. Handle SPDM protocol exchanges

### Example Test Flow

An external client should send:
1. **GET_VERSION** request to test version negotiation
2. **GET_CAPABILITIES** request to test capability exchange
3. Verify responses are properly formatted and returned over UART

## Architecture

```
External SPDM Client ←→ UART ←→ MCTP Server ←→ SPDM Responder
```

The MCTP server handles the physical UART transport and routes SPDM messages (type 5) to the SPDM responder task, which processes them and sends responses back through the same path.
