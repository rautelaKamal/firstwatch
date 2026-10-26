FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-php8.1 php8.1-mysql \
 && rm -rf /var/lib/apt/lists/*
COPY . /var/www/html
