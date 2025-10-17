# Copilot Instructions for Hubris (spdm-resp)

## Project Overview
- **Hubris** is a microcontroller OS for deeply-embedded, reliable systems. See `README.mkdn` and `doc/` for architecture and design rationale.
- The repo is organized by function: `app/` (application binaries), `drv/` (drivers/servers), `build/` (build system), `chips/` (chip support), `idl/` (Idol IPC interfaces), `lib/` (utility libraries), `sys/` (kernel/system), `task/` (tasks/services), `boards/` (board configs).

## Key Workflows
- **Build an image:**
  - Use `cargo xtask dist <app/app.toml>` to build firmware images. Example: `cargo xtask dist app/gimlet/app.toml`.
  - CI builds use GitHub Actions (`.github/workflows/build-boards.yml`, `build-one.yml`).
- **Testing:**
  - Run `cargo xtask test <test/app.toml>` for board-specific tests. See `README.mkdn` > "Testing Hubris" for board details and requirements.
  - Tests use ITM output, parsed by `humility test` (invoked by `cargo xtask test`).
- **Debugging:**
  - Debug via OpenOCD. Only one OpenOCD instance can connect at a time.
- **Signing/Release:**
  - SP signing jobs/scripts are in `.github/buildomat/jobs/` (e.g., `sign-sp1.sh`).
  - Releases are cut via `.github/workflows/release.yml` after building artifacts.

## Project Conventions
- **No-std, cross-compilation:** Most crates are `no_std` and cross-compiled for ARM MCUs. Test builds are disabled in many `Cargo.toml` files to avoid issues with RLS/rust-analyzer.
- **Features:** Hardware backends and board support are selected via Cargo features (see `Cargo.toml` in `task/`, `drv/`).
- **Idol for IPC:** IPC interfaces are defined in `idl/` using Idol. Codegen occurs via `build.rs` or build-dependencies.
- **Driver/server naming:**
  - `drv/SYSTEM-DEVICE` = driver for DEVICE on SYSTEM
  - `drv/SYSTEM-DEVICE-server` = server binary for DEVICE
- **Board configs:** Board-specific TOML files are in `boards/` and referenced in `app/` and CI workflows.

## Integration & Patterns
- **External dependencies:**
  - Uses `idol-runtime`, `userlib`, and other internal crates for IPC, system calls, and utilities.
  - Some drivers support multiple hardware backends, selected by features (see `drv/digest-server/README.md`).
- **Build system:**
  - Custom build logic in `build/xtask/` (see `src/lsp.rs` for task validation and build command construction).
- **CI/CD:**
  - Matrix builds for many boards; see `.github/workflows/build-boards.yml` for all supported targets.

## Examples
- To build and test for STM32F4 Discovery:
  ```sh
  cargo xtask dist app/demo-stm32f4-discovery/app.toml
  cargo xtask test test/tests-stm32fx/app.toml
  ```
- To add a new board, create a TOML in `boards/`, update `app/`, and add to CI matrix.

## References
- [Developer docs](doc/)
- [README.mkdn](README.mkdn)
- [CI workflows](.github/workflows/)
- [Board configs](boards/)
- [Build system](build/xtask/)

---
If any conventions or workflows are unclear, please request clarification or examples from maintainers.
