use std::time::Duration;

use ureq::Agent;

/// Build a ureq agent with the given global timeout. TLS verification stays enabled
/// (the ureq default) — callers should not disable it.
pub fn build_agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into()
}
