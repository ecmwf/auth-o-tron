//! Metrics collection and exposition for Prometheus.
//!
//! This module provides centralized metrics recording

mod recorder;

pub use recorder::{Metrics, MetricsRecorder};
