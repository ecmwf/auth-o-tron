// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::time::Duration;

use super::log_throttle::should_emit;

/// Upper bound for caches keyed by credentials or usernames supplied by callers.
pub const ATTACKER_KEYED_CACHE_SIZE: usize = 100_000;

const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);

/// Runs the cache-hit logger only when the value came from cache and the event's
/// throttle window allows it. The callback keeps each event's existing fields
/// and message while sharing the hit/throttle behaviour.
pub fn log_cache_hit<F>(was_cached: bool, event_name: &'static str, log: F)
where
    F: FnOnce(u64),
{
    if was_cached && let Some(suppressed_count) = should_emit(event_name, CACHE_HIT_LOG_WINDOW) {
        log(suppressed_count);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[test]
    fn attacker_keyed_caches_allow_one_hundred_thousand_entries() {
        assert_eq!(ATTACKER_KEYED_CACHE_SIZE, 100_000);
    }

    #[test]
    fn cache_hit_logger_ignores_cache_misses() {
        static CALLS: AtomicU64 = AtomicU64::new(0);
        log_cache_hit(false, "utils.cache.test.miss", |_| {
            CALLS.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    }
}
