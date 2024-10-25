# Use the official Rust image as the base image
FROM rust:1.72

# Set the working directory inside the container
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files to the container
COPY . .

# Build the dependencies
RUN cargo build --release

# Set the entrypoint command to run the application
CMD ["./target/release/letmeout"]

