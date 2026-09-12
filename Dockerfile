FROM rust:1-bookworm AS builder

WORKDIR /app

COPY backend ./backend

WORKDIR /app/backend
RUN cargo build --release --bin vortex-dfs

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/backend/target/release/vortex-dfs /usr/local/bin/vortex-dfs

ENV VORTEX_HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["vortex-dfs"]
