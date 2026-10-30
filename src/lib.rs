//! Shibboleth SP configuration checker. The `shibcheck` binary is a thin CLI over these modules.

pub mod baseline;
pub mod checks;
pub mod cli;
pub mod config;
pub mod diff;
pub mod filter;
pub mod fix;
pub mod http;
pub mod init_test_idp;
pub mod location;
pub mod migrate;
pub mod model;
pub mod output;
pub mod parsers;
pub mod rc_config;
pub mod result;
pub mod suppress;
#[cfg(test)]
mod testutil;
pub mod watch;
