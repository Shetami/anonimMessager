#!/bin/sh
# One-time setup for docker-compose.yml.
#   ./init.sh relay.example.com [public-ip [interface-ip]]
# Writes .env, secrets/turn-secret and secrets/turnserver.conf (all git-ignored).
set -eu
cd "$(dirname "$0")"

domain=${1:?usage: ./init.sh <domain> [public-ip]}
ip=${2:-$(curl -4fsS https://api.ipify.org)}
# Address on the server's own interface. Differs from the public one when the
# provider uses NAT; coturn then needs the public/private mapping.
local_ip=${3:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')}
external=$ip
if [ -n "$local_ip" ] && [ "$local_ip" != "$ip" ]; then
  external="$ip/$local_ip"
fi

mkdir -p secrets
chmod 700 secrets
if [ ! -s secrets/turn-secret ]; then
  (umask 077; openssl rand -hex 32 > secrets/turn-secret)
fi
secret=$(cat secrets/turn-secret)

(umask 077; sed -e "s/__SECRET__/$secret/" -e "s#__EXTERNAL_IP__#$external#" turnserver.docker.conf > secrets/turnserver.conf)
# Both containers run as unprivileged users and read these through bind
# mounts; the 700 directory keeps other host users out.
chmod 644 secrets/turn-secret secrets/turnserver.conf

printf 'DOMAIN=%s\nPUBLIC_IP=%s\n' "$domain" "$ip" > .env

echo "Domain: $domain  Public IP: $ip  TURN external-ip: $external"
echo "Point $domain's A record at $ip, open TCP 80/443, TCP+UDP 3478 and UDP 49160-49999, then:"
echo "  docker compose up -d --build"
