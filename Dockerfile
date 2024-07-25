
# Stage 1: Build cargo chef recipe
FROM rust:slim-buster as chef
RUN cargo install cargo-chef
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && apt-get clean
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Build and cache dependencies
FROM rust:slim-buster as cacher
RUN cargo install cargo-chef
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && apt-get clean
WORKDIR /app
COPY --from=chef /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Build project
FROM rust:slim-buster as builder
RUN apt-get update && apt-get install -y libssl-dev pkg-config build-essential && apt-get clean
WORKDIR /app
COPY . .

# Copy cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# Build
RUN cargo build --release

# Stage 4: Final image
FROM debian:buster-slim as authotron

# Runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean
WORKDIR /app

# Copy the binary from the build stage
COPY --from=builder /app/target/release/rust-authotron .

COPY ./src/config.yaml /app/src/config.yaml

# Define the default command to run the application
CMD ["/app/rust-authotron"]
