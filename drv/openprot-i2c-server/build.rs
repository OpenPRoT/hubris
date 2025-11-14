// Copyright 2024 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Simple mock I2C server build - just need notifications
    build_util::expose_target_board();
    build_util::build_notifications()?;

    Ok(())
}
