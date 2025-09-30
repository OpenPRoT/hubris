// Licensed under the Apache-2.0 license

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    idol::Generator::new()
        .with_counters(
            idol::CounterSettings::default().with_server_counters(false),
        )
        .build_server_support(
            "../../idl/rng.idol",
            "server_stub.rs",
            idol::server::ServerStyle::InOrder,
        )?;
    Ok(())
}