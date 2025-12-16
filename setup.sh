#!/bin/bash
echo "JWT Attack & Defense Playground Setup"
echo "======================================"
echo

# Generate RSA keys for algorithm confusion demonstrations
echo "Generating RSA key pair..."
mkdir -p keys
openssl genrsa -traditional -out keys/private.pem 2048 2>/dev/null
openssl rsa -in keys/private.pem -pubout -out keys/public.pem 2>/dev/null
echo "✓ RSA keys generated in keys/ directory"
echo

echo "✓ Setup complete!"
echo
echo "Next steps:"
echo "    1. Run: docker-compose up --build"
echo "    2. Open http://localhost in your browser"
echo
echo "Note: Make sure Docker is running before starting!"
