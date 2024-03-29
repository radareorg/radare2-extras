FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install basic utilities (optional)
RUN apt-get update && apt-get install -y \
    curl \
    git \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Your command here
RUN curl -L -s https://rev.ng/downloads/revng-distributable/master/install.sh | bash

COPY revng.sh /

ENTRYPOINT /revng.sh
