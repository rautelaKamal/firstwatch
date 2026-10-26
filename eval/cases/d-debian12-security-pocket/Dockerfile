FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx php8.2-fpm php8.2-mysql \
 && rm -rf /var/lib/apt/lists/*
