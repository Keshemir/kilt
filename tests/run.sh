#!/bin/sh
# Runs tests/security.py in a throwaway container with systemd: ./tests/run.sh [en|ru]
set -eu
LANG_UI="${1:-en}"
case "$LANG_UI" in
  en|ru) ;;
  *) echo "usage: $0 [en|ru] (unknown language: $LANG_UI)" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
docker build -q -t kilt-test tests >/dev/null
docker rm -f kilt-test >/dev/null 2>&1 || true
docker run -d --name kilt-test --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v kilt-test-docker:/var/lib/docker \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp kilt-test >/dev/null
trap 'docker rm -f kilt-test >/dev/null 2>&1 || true' EXIT
if ! docker exec kilt-test timeout 180 sh -c 'until systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"; do sleep 1; done'; then
  echo "systemd in the test container did not start in 180 seconds" >&2
  exit 1
fi
docker exec kilt-test systemctl start docker
docker cp . kilt-test:/root/kilt-src
docker exec -e KILT_TEST_LANG="$LANG_UI" kilt-test python3 /root/kilt-src/tests/security.py
