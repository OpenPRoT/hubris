// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 Advanced Micro Devices, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    build_util::expose_target_board();
    build_util::build_notifications()?;

    idol::Generator::new().build_server_support(
        "../../idl/openprot-digest.idol",
        "server_stub.rs",
        idol::server::ServerStyle::InOrder,
    )?;

    // Post-process the generated file to fix zerocopy derives
    let out_dir = std::env::var("OUT_DIR")?;
    let stub_path = std::path::Path::new(&out_dir).join("server_stub.rs");

    if let Ok(content) = std::fs::read_to_string(&stub_path) {
        // Replace zerocopy_derive:: with zerocopy:: for compatibility with zerocopy 0.8.x
        let modified_content = content
            .replace("zerocopy_derive::FromBytes", "zerocopy::FromBytes")
            .replace("zerocopy_derive::KnownLayout", "zerocopy::KnownLayout")
            .replace("zerocopy_derive::Immutable", "zerocopy::Immutable")
            .replace("zerocopy_derive::Unaligned", "zerocopy::Unaligned")
            .replace("zerocopy_derive::IntoBytes", "zerocopy::IntoBytes");
        std::fs::write(&stub_path, modified_content)?;
    }

    Ok(())
}
