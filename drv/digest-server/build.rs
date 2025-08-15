// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    build_util::expose_target_board();
    build_util::build_notifications()?;    
    
    idol::Generator::new().build_server_support(
        "../../idl/digest.idol",
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
