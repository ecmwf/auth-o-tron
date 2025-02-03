###############################
# Stage 1: Prepare Cargo Chef Recipe
###############################
FROM rust:1.84-slim-bookworm AS chef
# Install cargo-chef (locked version for reproducibility)
RUN cargo install cargo-chef --locked
# Install build tools (openssl, pkg-config, build-essential, etc.)
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy the project files needed to determine dependencies
COPY . .
# Prepare the dependency recipe
RUN cargo chef prepare --recipe-path recipe.json

###############################
# Stage 2: Cache Dependencies
###############################
FROM rust:1.84-slim-bookworm AS cacher
RUN cargo install cargo-chef --locked
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy the dependency recipe from the chef stage
COPY --from=chef /app/recipe.json recipe.json
# Build the dependency layers (release profile)
RUN cargo chef cook --release --recipe-path recipe.json

###############################
# Stage 3: Build the Project
###############################
FROM rust:1.84-slim-bookworm AS builder
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Copy full source code
COPY . .
# Reuse the dependency cache
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
# Build the application in release mode
RUN cargo build --release

###############################
# Stage 4: Production Release Image
###############################
# Use a very small base image.
FROM gcr.io/distroless/cc as release
ARG VERSION
LABEL version=$VERSION
WORKDIR /app
# Update the binary name to match what Cargo produced.
COPY --from=builder /app/target/release/rust-authotron /app/auth-o-tron
# Optionally, copy configuration files if needed. (could be useful when testing locally)
# Do not comment out the line below, we will mount the config file using a configmap
# COPY ./src/config.yaml /app/src/config.yaml
USER nonroot:nonroot
ENTRYPOINT ["/app/auth-o-tron"]


###############################
# Stage 5: Debug Image
###############################
FROM debian:bookworm-slim AS debug
ARG VERSION
LABEL version=$VERSION
RUN apt-get update && apt-get install -y ca-certificates bash && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Update the binary name to match what Cargo produced.
COPY --from=builder /app/target/release/rust-authotron /app/auth-o-tron
# Optionally, copy configuration files if needed. (could be useful when testing locally)
# Do not comment out the line below, we will mount the config file using a configmap
# COPY ./src/config.yaml /app/src/config.yaml
ENTRYPOINT ["/app/auth-o-tron"]

