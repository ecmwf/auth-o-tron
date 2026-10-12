// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Per-replica, per-client-IP fixed-window limits for the token and revocation endpoints.

use crate::config::OAuthEndpointRateLimit;
use http::HeaderMap;
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Endpoint {
    Token,
    Revoke,
}

struct Window {
    started: Instant,
    used: u32,
}

pub(crate) struct EndpointRateLimiter {
    window: Duration,
    token_limit: u32,
    revoke_limit: u32,
    max_tracked: usize,
    trusted: Vec<IpNet>,
    windows: Mutex<HashMap<(Endpoint, IpAddr), Window>>,
}

impl EndpointRateLimiter {
    pub(crate) fn new(config: &OAuthEndpointRateLimit) -> Result<Self, &'static str> {
        let trusted = config
            .trusted_proxies
            .iter()
            .map(|cidr| cidr.parse().map_err(|_| "invalid trusted proxy CIDR"))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            window: Duration::from_secs(config.window_seconds),
            token_limit: config.token_requests_per_window,
            revoke_limit: config.revoke_requests_per_window,
            max_tracked: config.max_tracked_clients,
            trusted,
            windows: Mutex::new(HashMap::new()),
        })
    }

    /// The TCP peer, or for a trusted proxy peer the right-most `X-Forwarded-For`
    /// address outside `trusted_proxies`. With `10.0.0.0/8` trusted and peer
    /// `10.0.0.5`: `X-Forwarded-For: 198.51.100.7, 10.0.0.9` yields `198.51.100.7`;
    /// a missing or unparsable header (`unknown`, `198.51.100.7:443`) yields the peer.
    pub(crate) fn client_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer?;
        if !self.is_trusted(peer) {
            return Some(peer);
        }
        let mut last_trusted = peer;
        for value in headers.get_all("x-forwarded-for").iter().rev() {
            let Ok(value) = value.to_str() else {
                return Some(last_trusted);
            };
            for entry in value.rsplit(',') {
                let Ok(ip) = entry.trim().parse::<IpAddr>() else {
                    return Some(last_trusted);
                };
                if !self.is_trusted(ip) {
                    return Some(ip);
                }
                last_trusted = ip;
            }
        }
        Some(last_trusted)
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// Spends one request for `ip`; `Err` carries the seconds until the window resets.
    /// Requests without a known peer share one bucket.
    pub(crate) fn admit(&self, endpoint: Endpoint, ip: Option<IpAddr>) -> Result<(), u64> {
        self.admit_at(endpoint, ip, Instant::now())
    }

    fn admit_at(&self, endpoint: Endpoint, ip: Option<IpAddr>, now: Instant) -> Result<(), u64> {
        let limit = match endpoint {
            Endpoint::Token => self.token_limit,
            Endpoint::Revoke => self.revoke_limit,
        };
        let key = (endpoint, bucket(ip));
        let full_window = self.window.as_secs().max(1);
        let Ok(mut windows) = self.windows.lock() else {
            return Err(full_window);
        };
        if !windows.contains_key(&key) && windows.len() >= self.max_tracked {
            windows.retain(|_, window| now.duration_since(window.started) < self.window);
            if windows.len() >= self.max_tracked {
                return Err(full_window);
            }
        }
        let window = windows.entry(key).or_insert(Window {
            started: now,
            used: 0,
        });
        let elapsed = now.duration_since(window.started);
        if elapsed >= self.window {
            *window = Window {
                started: now,
                used: 0,
            };
        }
        if window.used >= limit {
            let remaining = self
                .window
                .saturating_sub(now.duration_since(window.started));
            return Err(remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0));
        }
        window.used += 1;
        Ok(())
    }
}

/// IPv4 (and IPv4-mapped IPv6) addresses are keyed exactly; other IPv6 addresses by
/// their /64, the smallest prefix routinely assigned to one subscriber.
fn bucket(ip: Option<IpAddr>) -> IpAddr {
    match ip.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V6(v6)) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
        Some(ip) => ip,
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(trusted: &[&str], max_tracked: usize) -> EndpointRateLimiter {
        EndpointRateLimiter::new(&OAuthEndpointRateLimit {
            window_seconds: 60,
            token_requests_per_window: 2,
            revoke_requests_per_window: 1,
            max_tracked_clients: max_tracked,
            trusted_proxies: trusted.iter().map(|s| s.to_string()).collect(),
        })
        .unwrap()
    }

    fn ip(value: &str) -> Option<IpAddr> {
        Some(value.parse().unwrap())
    }

    #[test]
    fn fixed_window_is_per_endpoint_and_ip_and_resets() {
        let limiter = limiter(&[], 100);
        let now = Instant::now();
        let a = ip("198.51.100.7");
        assert!(limiter.admit_at(Endpoint::Token, a, now).is_ok());
        assert!(limiter.admit_at(Endpoint::Token, a, now).is_ok());
        assert_eq!(
            limiter.admit_at(Endpoint::Token, a, now + Duration::from_millis(500)),
            Err(60)
        );
        assert_eq!(
            limiter.admit_at(Endpoint::Token, a, now + Duration::from_secs(45)),
            Err(15)
        );
        assert!(limiter.admit_at(Endpoint::Revoke, a, now).is_ok());
        assert!(limiter.admit_at(Endpoint::Revoke, a, now).is_err());
        assert!(
            limiter
                .admit_at(Endpoint::Token, ip("198.51.100.8"), now)
                .is_ok()
        );
        assert!(
            limiter
                .admit_at(Endpoint::Token, a, now + Duration::from_secs(60))
                .is_ok()
        );
    }

    #[test]
    fn ipv6_shares_a_slash_64_and_mapped_ipv4_matches_ipv4() {
        let limiter = limiter(&[], 100);
        let now = Instant::now();
        assert!(
            limiter
                .admit_at(Endpoint::Revoke, ip("2001:db8::1"), now)
                .is_ok()
        );
        assert!(
            limiter
                .admit_at(Endpoint::Revoke, ip("2001:db8::ffff:1"), now)
                .is_err()
        );
        assert!(
            limiter
                .admit_at(Endpoint::Revoke, ip("2001:db8:0:1::1"), now)
                .is_ok()
        );
        assert!(
            limiter
                .admit_at(Endpoint::Revoke, ip("192.0.2.1"), now)
                .is_ok()
        );
        assert!(
            limiter
                .admit_at(Endpoint::Revoke, ip("::ffff:192.0.2.1"), now)
                .is_err()
        );
    }

    #[test]
    fn full_table_prunes_expired_windows_then_rejects_new_ips() {
        let limiter = limiter(&[], 1);
        let now = Instant::now();
        assert!(
            limiter
                .admit_at(Endpoint::Token, ip("192.0.2.1"), now)
                .is_ok()
        );
        assert_eq!(
            limiter.admit_at(Endpoint::Token, ip("192.0.2.2"), now),
            Err(60)
        );
        assert!(
            limiter
                .admit_at(Endpoint::Token, ip("192.0.2.1"), now)
                .is_ok()
        );
        let later = now + Duration::from_secs(60);
        assert!(
            limiter
                .admit_at(Endpoint::Token, ip("192.0.2.2"), later)
                .is_ok()
        );
    }

    #[test]
    fn forwarded_for_is_used_only_through_trusted_proxies() {
        let limiter = limiter(&["10.0.0.0/8"], 100);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.9, 198.51.100.7, 10.0.0.9".parse().unwrap(),
        );
        assert_eq!(
            limiter.client_ip(ip("10.0.0.5"), &headers),
            ip("198.51.100.7")
        );
        assert_eq!(
            limiter.client_ip(ip("192.0.2.1"), &headers),
            ip("192.0.2.1")
        );
        assert_eq!(
            limiter.client_ip(ip("::ffff:10.0.0.5"), &headers),
            ip("198.51.100.7")
        );
        headers.insert("x-forwarded-for", "unknown, 10.0.0.9".parse().unwrap());
        assert_eq!(limiter.client_ip(ip("10.0.0.5"), &headers), ip("10.0.0.9"));
        assert_eq!(
            limiter.client_ip(ip("10.0.0.5"), &HeaderMap::new()),
            ip("10.0.0.5")
        );
        headers.insert("x-forwarded-for", "198.51.100.7:443".parse().unwrap());
        assert_eq!(limiter.client_ip(ip("10.0.0.5"), &headers), ip("10.0.0.5"));
        let untrusting = super::tests::limiter(&[], 100);
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(
            untrusting.client_ip(ip("10.0.0.5"), &headers),
            ip("10.0.0.5")
        );
        assert_eq!(limiter.client_ip(None, &headers), None);
    }
}
