// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::sync::LazyLock;
use std::time::Duration;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Shared connection pool for all HTTP-based server-side providers.
pub static PROVIDER_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("provider HTTP client configuration must be valid")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_timeout_defaults_are_explicit() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(2));
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(4));
    }
}
