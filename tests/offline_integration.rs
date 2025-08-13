use base64::Engine;
use jsonwebtoken::TokenData;
use reqwest::Client;
use std::process::Stdio;
use tokio::{fs, time};
use tokio::{io::AsyncReadExt, process::Command};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Option<String>,
    username: Option<String>,
    exp: Option<usize>,
    iss: Option<String>,
    roles: Vec<String>,
}

#[tokio::test]
async fn integration_plain_auth_flow() {
    // Start the service
    let config = r#"
auth:
  timeout_in_ms: 3000
providers:
  - name: "ECMWF API Provider"
    use std::{fs, process::Stdio};
    uri: https://api.ecmwf.int/v1
    realm: "ecmwf"
  - name: "Plain provider"
    type: "plain"
    realm: "ecmwf"
    users:
        - username: adam
          password: admin
          roles:
            - user
        - username: eve
          password: admin
          roles:
            - superuser
  - name: "Plain provider"
    type: "plain"
    realm: "other"
    users:
        - username: adam
          password: other
          roles:
            - user

augmenters:
  - name: "Polytope plain admin augmenter"
    type: "plain"
    realm: "ecmwf"
    roles:
        admin:
            - eve
            - adam
        
store:
  enabled: false
services: []
jwt:
  exp: 3600
  iss: authotron-test
  secret: test-secret
bind_address: 0.0.0.0:8080
                "#;
    if cfg!(windows) {
        let config_path = "/tmp/authotron-test-config.yaml";
        std::fs::write(config_path, config).unwrap();

        // Wrap the test in a Result to allow ? and ensure cleanup
        let test_result = async {
            // Find the binary in target/debug, build if missing
            let mut bin_path = std::env::current_dir().unwrap();
            bin_path.push("target");
            bin_path.push("debug");
            bin_path.push("authotron");
            println!("Using auth-o-tron binary at {:?}", bin_path);
            if cfg!(windows) {
                bin_path.set_extension("exe");
            }
            if !bin_path.exists() {
                let status = std::process::Command::new("cargo")
                    .arg("build")
                    .status()
                    .expect("Failed to run cargo build");
                assert!(status.success(), "cargo build failed");
                assert!(
                    bin_path.exists(),
                    "auth-o-tron binary not found after build"
                );
            }
            let child = Command::new(bin_path)
                .arg("--config")
                .arg(config_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to start auth-o-tron");

            // Wait for the service to be up (async)
            let client = Client::new();
            let url = "http://localhost:8080/health";
            for _ in 0..10 {
                if let Ok(resp) = client.get(url).send().await {
                    if resp.status().is_success() {
                        break;
                    }
                }
                time::sleep(time::Duration::from_millis(500)).await;
            }

            // 1. Test success auth
            // Base64 encode "adam:admin"
            let credentials = "adam:admin";
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            let header_value = format!("Basic {}", encoded);
            let resp = client
                .post("http://localhost:8080/auth/plain")
                .header("Authorization", header_value)
                .send()
                .await
                .expect("Failed to send request");
            assert!(resp.status().is_success(), "Expected 200 OK");
            // decode auth header which is a jwt token and check roles are exactly user and admin
            let token = resp
                .headers()
                .get("Authorization")
                .unwrap()
                .to_str()
                .unwrap();
            let claims: TokenData<Claims> = jsonwebtoken::decode(
                token,
                &jsonwebtoken::DecodingKey::from_secret("test-secret".as_ref()),
                &jsonwebtoken::Validation::default(),
            )
            .unwrap();
            let roles = &claims.claims.roles;
            assert_eq!(roles.len(), 2);
            assert!(roles.iter().any(|r| r == "user"), "Expected user role");
            assert!(roles.iter().any(|r| r == "admin"), "Expected admin role");

            // 2. Test failure auth
            let credentials = "adam:wrongpassword";
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            let header_value = format!("Basic {}", encoded);
            let resp = client
                .post("http://localhost:8080/auth/plain")
                .header("Authorization", header_value)
                .send()
                .await
                .expect("Failed to send request");
            assert_eq!(resp.status(), 401);

            // 3. Test realms separation
            let credentials = "adam:other";
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            let header_value = format!("Basic {}", encoded);
            let resp = client
                .post("http://localhost:8080/auth/plain")
                .header("Authorization", header_value)
                .send()
                .await
                .expect("Failed to send request");
            assert!(
                resp.status().is_success(),
                "Expected 200 OK but got {}",
                resp.status()
            );
            let token = resp
                .headers()
                .get("Authorization")
                .unwrap()
                .to_str()
                .unwrap();
            let claims: TokenData<Claims> = jsonwebtoken::decode(
                token,
                &jsonwebtoken::DecodingKey::from_secret("test-secret".as_ref()),
                &jsonwebtoken::Validation::default(),
            )
            .unwrap();
            let roles = &claims.claims.roles;
            assert_eq!(roles.len(), 1);
            assert!(roles.iter().any(|r| r == "user"), "Expected only user role");

            Ok::<_, Box<dyn std::error::Error>>(child)
        }
        .await;

        // Always run cleanup, even if the test failed
        match test_result {
            Ok(mut child) => {
                let _ = child.kill().await;
                // Print logs from stdout and stderr
                if let Some(mut out) = child.stdout.take() {
                    let mut buf = Vec::new();
                    let _ = out.read_to_end(&mut buf).await;
                    if !buf.is_empty() {
                        println!("[auth-o-tron stdout]\n{}", String::from_utf8_lossy(&buf));
                    }
                }
                if let Some(mut err) = child.stderr.take() {
                    let mut buf = Vec::new();
                    let _ = err.read_to_end(&mut buf).await;
                    if !buf.is_empty() {
                        eprintln!("[auth-o-tron stderr]\n{}", String::from_utf8_lossy(&buf));
                    }
                }
            }
            Err(e) => {
                // If we failed to get the child, try to kill any running process anyway
                // (best effort, not guaranteed)
                // Optionally print a message here
                // Remove the config file
                let _ = fs::remove_file(config_path);
                panic!("Test failed: {e}");
            }
        }
        // Remove the config file
        let _ = fs::remove_file(config_path);
    }
}
