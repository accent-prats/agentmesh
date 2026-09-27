#!/usr/bin/env bash
# Generate self-signed TLS certificates for local development.
# Run once: bash infrastructure/nginx/generate-certs.sh
#
# Set SERVER_IP to include your server's IP as a SAN in the portal cert so
# that https://<IP> validates without a hostname mismatch warning:
#   SERVER_IP=192.0.2.10 bash infrastructure/nginx/generate-certs.sh
set -euo pipefail

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

for domain in portal.local growthbook.local; do
  if [[ -f "$CERT_DIR/$domain.crt" ]]; then
    echo "  ✓ $domain.crt already exists, skipping"
    continue
  fi
  echo "  Generating $domain …"

  # For portal.local: optionally add the server IP so https://<IP> validates.
  san="DNS:$domain"
  if [[ "$domain" == "portal.local" && -n "${SERVER_IP:-}" ]]; then
    san="$san,IP:$SERVER_IP"
    echo "    (including IP SAN: $SERVER_IP)"
  fi

  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$CERT_DIR/$domain.key" \
    -out    "$CERT_DIR/$domain.crt" \
    -subj   "/CN=$domain" \
    -addext "subjectAltName=$san"
  echo "  ✓ $domain.crt"
done

echo ""
echo "Certificates written to $CERT_DIR"
echo "Add these to your system trust store (or browser) to avoid cert warnings."
echo "On macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_DIR/portal.local.crt"
echo "On Linux: sudo cp $CERT_DIR/*.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
