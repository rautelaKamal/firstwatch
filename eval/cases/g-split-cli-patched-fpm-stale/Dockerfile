FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx php8.4-fpm php8.4-cli \
 && rm -rf /var/lib/apt/lists/*
