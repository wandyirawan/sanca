# syntax=docker/dockerfile:1.7
# ---------- stage 1: builder ----------
FROM lukemathwalker/cargo-chef:latest-rust-1-slim-bookworm AS chef
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# cache lapisan dependency
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# sqlx offline: tidak butuh database saat build
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin sanca \
 && strip target/release/sanca

# ---------- stage 2: runtime ----------
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/release/sanca /app/sanca
USER nonroot:nonroot
ENV SQLX_OFFLINE=true
ENV IAM_BIND=0.0.0.0:8080 SANCA_ENV=prod
EXPOSE 8080
ENTRYPOINT ["/app/sanca"]
