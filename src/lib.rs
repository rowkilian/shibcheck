//! Shibboleth SP configuration checker. The `shibcheck` binary is a thin CLI over these modules.

pub mod checks;
pub mod cli;
pub mod config;
pub mod diff;
pub mod filter;
pub mod fix;
pub mod http;
pub mod init_test_idp;
pub mod location;
pub mod model;
pub mod output;
pub mod parsers;
pub mod rc_config;
pub mod result;
#[cfg(test)]
mod testutil;
pub mod watch;
