#!/bin/sh
set -e
# Running as root: make the cert volume writable, then drop privileges.
if [ "$(id -u)" = "0" ]; then
	chown -R nonroot:nonroot "${CERT_DIR:-/data}"
	exec su-exec nonroot /edns "$@"
fi
exec /edns "$@"
