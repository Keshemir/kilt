FROM debian:13
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus libpam-systemd openssh-server openssh-client sudo nftables acl cron \
      python3 docker.io docker-cli docker-compose procps iproute2 ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
