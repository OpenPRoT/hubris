# AST1060 I2C Scaffold Application

This is a test application for the AST1060 that includes the mock I2C server along with basic system tasks. It's designed to provide a scaffold for testing I2C-related functionality on the AST1060 platform.

## Features

- **Mock I2C Server**: Includes the simplified mock I2C server task for testing I2C protocol compliance
- **UART Driver**: Basic UART driver for console output and debugging
- **Hello World Task**: Simple demonstration task that can interact with both UART and I2C
- **JTAG Support**: Optional JTAG halt feature for debugging

## Tasks

- `jefe`: System supervisor task
- `idle`: Low-priority idle task
- `uart_driver`: AST1060 UART driver for console I/O
- `i2c`: Mock I2C server with `mock-only` feature enabled
- `helloworld`: Test task with access to both UART and I2C services

## Usage

Build the application:
```bash
cargo xtask build app/ast1060-i2c-scaffold/app.toml
```

Build with JTAG halt for debugging:
```bash
cargo xtask build app/ast1060-i2c-scaffold/app.toml --feature jtag-halt
```

## I2C Testing

The mock I2C server provides a lightweight testing environment for I2C protocol compliance without requiring actual I2C hardware. The `helloworld` task can be modified to include I2C client code for testing various I2C operations.