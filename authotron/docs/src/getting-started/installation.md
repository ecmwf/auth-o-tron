# Installation

## Docker

Pull the latest image from the ECMWF container registry:

```bash
docker pull eccr.ecmwf.int/auth-o-tron/auth-o-tron:0.3.0
```

## Build from Source

Clone the repository and build with Cargo:

```bash
git clone https://github.com/ecmwf/auth-o-tron.git
cd auth-o-tron
cargo build --release
```

The binary is written to `target/release/authotron`.

### Requirements

- Rust stable (edition 2024)

## Configuration

Auth-O-Tron reads its configuration from a YAML file. Set the path with the `AOT_CONFIG_PATH` environment variable, or place it at `./config.yaml` (the default).

See the [Configuration](../configuration/README.md) section for the full reference.
