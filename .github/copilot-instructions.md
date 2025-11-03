# Hubris Development Guide for AI Coding Agents

Hubris is a microcontroller operating environment for deeply-embedded systems with strict reliability requirements. This is NOT a traditional RTOS—understand the architecture before making changes.

## Core Architecture Principles

**Task-Based Design**: Hubris applications consist of a fixed set of tasks defined at build time in `app.toml` files. Tasks cannot be created or destroyed at runtime—this is intentional for reliability and resource predictability.

**Synchronous IPC**: All inter-task communication uses synchronous message passing. A sending task blocks until the receiver processes the message and replies. This eliminates queuing overhead, prevents fault amplification, and makes the system easier to reason about.

**Strict Priority Scheduling**: Tasks have numeric priorities (0 = highest). The highest-priority ready task always runs. No time-slicing within a priority level—use separate priorities for full preemption.

**Memory Isolation**: Tasks are separately compiled at non-overlapping addresses with full memory isolation. Code is not shared between tasks—if three tasks use the same library, three copies exist in flash.

## Build System (`cargo xtask`)

**DO NOT use `cargo build` directly.** Hubris has a custom build system:

- `cargo xtask dist app/NAME/app.toml` - Build complete system image
- `cargo xtask build app/NAME/app.toml TASKNAME` - Build single task for iteration
- `cargo xtask clippy app/NAME/app.toml TASKNAME` - Run clippy on a task
- `cargo xtask flash app/NAME/app.toml` - Build and flash to hardware
- `cargo xtask sizes app/NAME/app.toml` - Analyze memory usage

Images are built to `target/APPNAME/dist/`. The build system handles complex multi-architecture compilation, address allocation, and image assembly.

## Application Configuration (`app.toml`)

Located in `app/*/app.toml`. Critical sections:

```toml
[kernel]
name = "app-name"
requires = {flash = 20000, ram = 3072}

[tasks.task_name]
name = "task-crate-name"      # Corresponds to drv/ or task/ crate
priority = 2                   # 0 = highest priority
max-sizes = {flash = 8192, ram = 1024}
uses = ["usart2", "gpioa"]     # Hardware peripherals from board.toml
task-slots = ["other_task"]    # IPC dependencies
start = true                   # Start on boot
notifications = ["timer"]      # Notification bits
interrupts = {"usart2.irq" = "usart-irq"}  # IRQ mappings
```

Tasks reference crates in `drv/` (drivers) or `task/` (reusable tasks). Board-specific peripheral definitions come from `boards/*.toml`.

## Idol: Interface Definition Language

Hubris uses Idol for IPC interfaces. IDL files in `idl/` generate client/server stubs:

**Server side** (`build.rs`):
```rust
idol::Generator::new()
    .with_counters(idol::CounterSettings::default())
    .build_server_support("../../idl/myapi.idol", "server_stub.rs", idol::server::ServerStyle::InOrder)?;
```

**Client side** (`build.rs`):
```rust
idol::client::build_client_stub("../../idl/myapi.idol", "client_stub.rs")?;
```

Client crates typically live in `drv/NAME-api/` or `task/NAME-api/`. Servers implement operations defined in `.idol` files.

## Directory Structure

- `app/` - Application firmware crates (e.g., `app/gimlet`, `app/oxide-rot-1`)
- `boards/` - Board definitions with peripheral mappings (`.toml`)
- `chips/` - Chip-specific PACs and debugging support
- `drv/` - Drivers: `drv/CHIP-DEVICE` (library) or `drv/CHIP-DEVICE-server` (task)
- `idl/` - Idol interface definitions
- `sys/kern` - The kernel (runs in privileged mode)
- `sys/abi` - Kernel/userspace ABI definitions
- `sys/userlib` - User task library with syscall stubs
- `task/` - Reusable tasks (e.g., `task-jefe` supervisor, `task-net` networking)
- `build/xtask` - Custom build system implementation

## Key Conventions

**Priority Assignment**: Lower numbers = higher priority. Priority 0 is typically `task-jefe` (supervisor). Drivers often run at priority 1-2. Application tasks at lower priorities.

**Uphill Rule**: Tasks can only send IPC to equal or higher priority tasks. This prevents priority inversion and deadlock.

**Peripheral Ownership**: Each peripheral is owned by exactly one task via `uses = ["peripheral"]` in `app.toml`. Never share peripheral access.

**Task Slots**: The `task-slots = ["other_task"]` mechanism creates an IPC handle to another task. The kernel enforces this at build time.

**Notifications**: Lightweight, asynchronous signaling mechanism. Tasks can post notification bits to themselves or others. Use for timers and interrupts.

## Debugging with Humility

Install: `cargo install --git https://github.com/oxidecomputer/humility.git --locked humility-bin`

- `humility -d APP.toml` - Attach debugger
- `humility tasks` - List tasks and states
- `humility readvar TASK::VAR` - Read task variable
- `humility manifest` - Show task memory map

Archive files (`app.zip`) contain debug info for post-mortem analysis.

## Common Patterns

**Creating a new driver server**:
1. Add IDL file to `idl/NAME.idol`
2. Create `drv/NAME-api/` for client crate
3. Create `drv/NAME-server/` for server implementation
4. Add server task to `app.toml` with appropriate priority and `uses`
5. Add client API to tasks that need it via `task-slots`

**Memory-mapped peripherals**: Use PAC from `chips/CHIPNAME/chip/src/lib.rs`. Peripherals are zero-sized types that provide register access.

**Leases**: For large data transfers in IPC, use memory leases (`Lease::read_only()`, `Lease::read_write()`). These grant temporary access to caller's memory without copying.

## Workspace Dependencies

Defined in workspace root `Cargo.toml`. Hubris depends heavily on:
- `idol` / `idol-runtime` - IPC code generation
- `zerocopy` - Zero-copy parsing
- `hubpack` - Serialization for IPC
- Chip PACs: `stm32h7`, `stm32f4`, `lpc55-pac`, `ast1060-pac`

OpenPRoT-specific: Uses OpenPRoT platform crates on the `i2c-hardware` branch.

## Testing

Tests live in `test/tests-BOARD/`. Use `cargo xtask test app/TEST.toml` to build, flash, and run tests via Humility.

## What NOT to do

- Don't use `cargo build` or `cargo run` directly
- Don't create tasks dynamically (impossible by design)
- Don't send IPC "downhill" to lower priority tasks (kernel rejects this)
- Don't share peripheral access between tasks
- Don't use async/await for IPC (it's synchronous by design)
- Don't add generic advice like "write tests" without Hubris-specific context

## Documentation

- `doc/` - AsciiDoc documentation rendered at https://oxidecomputer.github.io/hubris
- `README.mkdn` - Project overview and getting started
- `FAQ.mkdn` - Design philosophy and comparisons to other systems
- `CONTRIBUTING.md` - Contribution guidelines

## Current State

This is production firmware for Oxide Computer Company's server products. It's open source but primarily developed for internal use. External PRs welcome but may take time to review.
