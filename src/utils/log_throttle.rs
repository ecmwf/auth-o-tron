use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct WindowState {
    window_started_at: Instant,
    suppressed: u64,
}

static LOG_WINDOWS: OnceLock<Mutex<HashMap<String, WindowState>>> = OnceLock::new();

fn windows() -> &'static Mutex<HashMap<String, WindowState>> {
    LOG_WINDOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `Some(suppressed_count)` when a log for `key` should be emitted,
/// otherwise `None` and the event is counted as suppressed for the active window.
pub fn should_emit(key: &str, interval: Duration) -> Option<u64> {
    let mut map = windows().lock().expect("log throttle mutex poisoned");
    let now = Instant::now();

    match map.get_mut(key) {
        Some(state) => {
            if now.duration_since(state.window_started_at) >= interval {
                let suppressed = state.suppressed;
                state.window_started_at = now;
                state.suppressed = 0;
                Some(suppressed)
            } else {
                state.suppressed += 1;
                None
            }
        }
        None => {
            map.insert(
                key.to_string(),
                WindowState {
                    window_started_at: now,
                    suppressed: 0,
                },
            );
            Some(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_emit;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn emits_then_suppresses_then_emits_with_count() {
        let key = "test.log_throttle.emits_then_suppresses_then_emits_with_count";
        let interval = Duration::from_millis(20);

        assert_eq!(should_emit(key, interval), Some(0));
        assert_eq!(should_emit(key, interval), None);
        assert_eq!(should_emit(key, interval), None);

        sleep(Duration::from_millis(30));
        assert_eq!(should_emit(key, interval), Some(2));
    }
}
