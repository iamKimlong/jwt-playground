# JWT Attack & Defense Playground

Educational platform demonstrating real-world JWT security vulnerabilities and their defenses.

## Warning

This project contains **intentionally vulnerable code** for educational purposes. **NEVER** use these patterns in production environments.

## Features

### Vulnerabilities Demonstrated
- **"none" algorithm attack** - Bypassing signature verification
- **Algorithm confusion** - RS256 to HS256 confusion exploit
- **Weak secrets** - Brute-force attacks on JWT secrets
- **Token tampering** - Modifying claims without proper validation
- **Timing attacks** - Side-channel information leakage
- **Missing expiration** - Token replay vulnerabilities

### Defense Mechanisms
- Algorithm whitelisting
- Proper token validation
- Token blacklisting/revocation
- Constant-time comparisons
- Strong secret management
- Short-lived tokens with refresh mechanism

## Prerequisites

- Docker and Docker Compose
- OpenSSL (for key generation)

## Quick Start

1. **Clone and setup:**
```bash
git clone <repository>
cd jwt-playground
chmod +x setup.sh
./setup.sh
```

2. **Build and start containers:**
```bash
docker-compose up --build
```

3. **Access the application:**
    - Frontend: http://localhost
    - Backend API: http://localhost/api
    - API Documentation: http://localhost/api/docs

## Project Structure

```
jwt-playground/
├── backend/              # Go backend server
│   ├── main.go          # Main server implementation
│   ├── Dockerfile       # Backend container
│   ├── go.mod          
│   └── go.sum          
├── frontend/            # React frontend
│   ├── src/
│   │   ├── App.js      # Main React component
│   │   ├── App.css     # Styles
│   │   └── index.js    
│   ├── public/
│   │   └── index.html  
│   ├── package.json    
│   └── Dockerfile      
├── nginx/              
│   └── nginx.conf      # Nginx configuration
├── keys/               # RSA key pair (auto-generated)
│   ├── private.pem
│   └── public.pem
└── docker-compose.yml  
```

## API Endpoints

### Authentication
- `POST /api/login/vulnerable` - Login with vulnerable JWT (RS256)
- `POST /api/login/secure` - Login with secure JWT (HS256)

### Vulnerable Endpoints (For Learning)
- `GET /api/vulnerable/none-algorithm` - Accepts "none" algorithm
- `GET /api/vulnerable/algorithm-confusion` - RS256→HS256 confusion
- `POST /api/vulnerable/timing-attack` - Timing side-channel
- `GET /api/vulnerable/no-expiry` - No expiration validation

### Secure Endpoints
- `GET /api/secure/protected` - Properly secured endpoint
- `POST /api/secure/refresh` - Token refresh with blacklist
- `POST /api/secure/logout` - Secure logout

### Tools
- `POST /api/tools/tamper-token` - Token tampering tool
- `POST /api/tools/crack-weak-secret` - Weak secret cracker

## Learning Path

1. **Start with Overview** - Understand what JWT is and common vulnerabilities
2. **Explore Attacks** - Try each vulnerability in the Attacks tab
3. **Study Defenses** - See how proper implementation prevents attacks
4. **Use Tools** - Experiment with token manipulation

## Example Attack Scenarios

### 1. "none" Algorithm Attack
```bash
# Get a token from vulnerable login
curl -X POST http://localhost/api/login/vulnerable \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'

# Decode token, change algorithm to "none", remove signature
# Test on vulnerable endpoint
curl http://localhost/api/vulnerable/none-algorithm \
  -H "Authorization: Bearer eyJhbGc..."
```

### 2. Algorithm Confusion
- Login with vulnerable endpoint (gets RS256 token)
- Change algorithm header to HS256
- Sign with public key as HMAC secret
- Test on vulnerable/algorithm-confusion endpoint

### 3. Weak Secret Cracking
- Use the tool with common passwords
- Observe how weak secrets can be brute-forced

## Security Best Practices (from Defense Module)

1. **Use strong algorithms** - HS256 or RS256 with proper validation
2. **Whitelist algorithms** - Never accept "none" or unexpected algorithms
3. **Validate all claims** - exp, nbf, iss, aud
4. **Use strong secrets** - Minimum 256 bits for HMAC
5. **Short expiration** - 15 minutes for access tokens
6. **Implement refresh tokens** - With rotation and blacklisting
7. **Constant-time comparisons** - Prevent timing attacks
8. **Token blacklist** - For logout and token revocation

## Docker Commands

```bash
# Start services
docker-compose up

# Rebuild after changes
docker-compose up --build

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Access backend shell
docker exec -it jwt-backend sh
```

## Troubleshooting

**Port conflicts:**
```bash
# Change ports in docker-compose.yml
ports:
  - "8080:80"  # Use different port
```

**RSA keys not found:**
```bash
# Regenerate keys
./setup.sh
```

**Frontend not building:**
```bash
# Rebuild frontend container
docker-compose build frontend
```

## Educational Resources

- [JWT.io](https://jwt.io/) - JWT debugger
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT specification

## Contributing

This is an educational project. Contributions that add new attack vectors or defense mechanisms are welcome!

## License

MIT License - For educational purposes only

## Disclaimer

This software is provided for educational purposes only. The vulnerabilities demonstrated here are intentional and should never be used in production code. The authors are not responsible for any misuse of this software.
