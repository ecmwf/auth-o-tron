#![cfg(unix)]

use serde_json::Value;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct LogEvent {
    name: String,
    attributes: Value,
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn send_sigterm(&self) {
        // SAFETY: `self.child.id()` is the PID of the live child process owned by this guard.
        let result = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(result, 0, "failed to send SIGTERM to authotron child");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct SpawnedAuthotron {
    child: ChildGuard,
    events: mpsc::Receiver<LogEvent>,
    output: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
}

impl SpawnedAuthotron {
    fn output(&self) -> String {
        self.output.lock().expect("output lock poisoned").clone()
    }

    fn wait_for_event(&self, expected_name: &str) -> LogEvent {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = self.events.recv_timeout(remaining).unwrap_or_else(|error| {
                panic!(
                    "did not observe {expected_name:?} ({error})\nchild output:\n{}",
                    self.output()
                )
            });
            if event.name == expected_name {
                return event;
            }
        }
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            reader.join().expect("child output reader panicked");
        }
    }
}

struct ConfigFile(PathBuf);

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct DelayedUpstream {
    address: SocketAddr,
    request_started: mpsc::Receiver<()>,
    release_response: Option<mpsc::Sender<()>>,
    server: Option<JoinHandle<Result<(), String>>>,
}

impl DelayedUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed upstream");
        let address = listener
            .local_addr()
            .expect("read delayed upstream address");
        let (request_started_tx, request_started) = mpsc::channel();
        let (release_response, release_response_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            let deadline = Instant::now() + EVENT_TIMEOUT;
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("timed out waiting for delayed upstream request".to_owned());
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };

            stream
                .set_read_timeout(Some(EVENT_TIMEOUT))
                .map_err(|error| error.to_string())?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Err("upstream client closed before sending headers".to_owned());
                }
                request.extend_from_slice(&buffer[..read]);
                if request.len() > 64 * 1024 {
                    return Err("upstream request headers were unexpectedly large".to_owned());
                }
            }

            let request = String::from_utf8_lossy(&request);
            if !request.starts_with("GET /who-am-i?token=slow-token ") {
                return Err(format!("unexpected upstream request: {request}"));
            }
            request_started_tx
                .send(())
                .map_err(|error| error.to_string())?;
            release_response_rx
                .recv_timeout(EVENT_TIMEOUT)
                .map_err(|error| error.to_string())?;

            let body = r#"{"uid":"graceful-user","email":"graceful@example.test"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
            Ok(())
        });

        Self {
            address,
            request_started,
            release_response: Some(release_response),
            server: Some(server),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn wait_until_requested(&self) {
        self.request_started
            .recv_timeout(EVENT_TIMEOUT)
            .expect("authotron did not start the delayed upstream request");
    }

    fn release(&mut self) {
        self.release_response
            .take()
            .expect("delayed response already released")
            .send(())
            .expect("delayed upstream stopped before release");
    }

    fn finish(mut self) {
        self.server
            .take()
            .expect("delayed upstream thread missing")
            .join()
            .expect("delayed upstream panicked")
            .expect("delayed upstream failed");
    }
}

fn write_config(upstream_url: &str, metrics_enabled: bool) -> ConfigFile {
    let mode = if metrics_enabled {
        "metrics-enabled"
    } else {
        "metrics-disabled"
    };
    let path = env::temp_dir().join(format!(
        "authotron-shutdown-{}-{mode}.yaml",
        std::process::id()
    ));
    let config = format!(
        r#"version: "2.0.0"
logging:
  level: "info"
  format: "json"
auth:
  timeout_in_ms: 10000
providers:
  - name: "Delayed ECMWF API"
    type: "ecmwf-api"
    uri: "{upstream_url}"
    realm: "ecmwf"
augmenters: []
store:
  enabled: false
services: []
jwt:
  exp: 3600
  iss: "authotron-shutdown-test"
  secret: "test-secret"
server:
  host: "127.0.0.1"
  port: 0
metrics:
  enabled: {metrics_enabled}
  port: 0
"#
    );
    fs::write(&path, config).expect("write authotron test config");
    ConfigFile(path)
}

fn spawn_output_reader(
    reader: impl Read + Send + 'static,
    stream_name: &'static str,
    events: mpsc::Sender<LogEvent>,
    output: Arc<Mutex<String>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let line = line.expect("read authotron child output");
            {
                let mut output = output.lock().expect("output lock poisoned");
                writeln!(output, "[{stream_name}] {line}").expect("append child output");
            }
            let Ok(record) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let Some(name) = record
                .pointer("/attributes/event.name")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let _ = events.send(LogEvent {
                name: name.to_owned(),
                attributes: record["attributes"].clone(),
            });
        }
    })
}

fn spawn_authotron(config_path: &PathBuf) -> SpawnedAuthotron {
    let mut command = Command::new(env!("CARGO_BIN_EXE_authotron"));
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("AOT_") {
            command.env_remove(key);
        }
    }
    for key in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env_remove(key);
    }
    let mut child = command
        .env("AOT_CONFIG_PATH", config_path)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn authotron binary");

    let stdout = child.stdout.take().expect("capture authotron stdout");
    let stderr = child.stderr.take().expect("capture authotron stderr");
    let output = Arc::new(Mutex::new(String::new()));
    let (events_tx, events) = mpsc::channel();
    let readers = vec![
        spawn_output_reader(stdout, "stdout", events_tx.clone(), output.clone()),
        spawn_output_reader(stderr, "stderr", events_tx, output.clone()),
    ];

    SpawnedAuthotron {
        child: ChildGuard { child },
        events,
        output,
        readers,
    }
}

fn event_port(event: &LogEvent) -> u16 {
    event.attributes["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .unwrap_or_else(|| panic!("event did not contain a bound port: {event:?}"))
}

async fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("poll authotron child") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "authotron did not exit after completing its in-flight request"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn run_shutdown_case(metrics_enabled: bool) {
    let mut upstream = DelayedUpstream::start();
    let config = write_config(&upstream.url(), metrics_enabled);
    let mut authotron = spawn_authotron(&config.0);

    let app_port = event_port(&authotron.wait_for_event("startup.server.listening"));
    let metrics_port = if metrics_enabled {
        Some(event_port(
            &authotron.wait_for_event("startup.metrics.listening"),
        ))
    } else {
        authotron.wait_for_event("startup.metrics.disabled");
        None
    };

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(EVENT_TIMEOUT)
        .build()
        .expect("build HTTP test client");
    let app_health = client
        .get(format!("http://127.0.0.1:{app_port}/health"))
        .send()
        .await
        .expect("request application health endpoint");
    assert_eq!(app_health.status(), reqwest::StatusCode::OK);

    if let Some(metrics_port) = metrics_port {
        let metrics = client
            .get(format!("http://127.0.0.1:{metrics_port}/metrics"))
            .send()
            .await
            .expect("request metrics endpoint");
        assert_eq!(metrics.status(), reqwest::StatusCode::OK);
        assert!(
            metrics
                .text()
                .await
                .expect("read metrics response")
                .contains("authotron_http_requests_total"),
            "metrics endpoint should expose authotron metrics"
        );
    }

    let delayed_client = client.clone();
    let delayed_request = tokio::spawn(async move {
        let response = delayed_client
            .get(format!("http://127.0.0.1:{app_port}/authenticate"))
            .bearer_auth("slow-token")
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        Ok::<_, reqwest::Error>((status, body))
    });
    upstream.wait_until_requested();

    authotron.child.send_sigterm();
    let shutdown = authotron.wait_for_event("startup.shutdown.requested");
    assert_eq!(shutdown.attributes["signal"], "SIGTERM");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        authotron
            .child
            .child
            .try_wait()
            .expect("poll draining authotron child")
            .is_none(),
        "authotron exited before its in-flight request completed\n{}",
        authotron.output()
    );

    upstream.release();
    let (status, body) = tokio::time::timeout(PROCESS_TIMEOUT, delayed_request)
        .await
        .expect("in-flight request did not finish after upstream release")
        .expect("in-flight request task panicked")
        .expect("in-flight request failed");
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "Authenticated successfully");

    let status = wait_for_exit(&mut authotron.child.child).await;
    assert_eq!(
        status.code(),
        Some(0),
        "authotron did not exit successfully\n{}",
        authotron.output()
    );
    authotron.join_readers();
    upstream.finish();
}

// Keep both process-and-signal scenarios in one test so the harness cannot run them concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_drains_in_flight_request_and_exits_zero_with_and_without_metrics() {
    run_shutdown_case(true).await;
    run_shutdown_case(false).await;
}
