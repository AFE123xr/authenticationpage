# Secure Document Sharing & Authentication System

A robust, security-focused web application built with Rust and Axum for secure document storage, sharing, and user management.

## Features

- **End-to-End Security**: AES-256-GCM encryption for all uploaded documents.
- **Role-Based Access Control (RBAC)**: Admin, User, and Guest roles with granular permissions.
- **Secure Authentication**: Argon2 password hashing, session management with secure cookies, and rate-limiting.
- **Hardened Security Headers**: Strict CSP, HSTS, X-Frame-Options, and more.
- **Audit Logging**: Comprehensive activity logs for document access and system events.

## Prerequisites

- **Rust**: [Install Rust](https://www.rust-lang.org/tools/install) (Edition 2024).
- **OpenSSL**: Required for generating TLS certificates and the master encryption key.

## Setup Instructions

### 1. Generate the Master Encryption Key
This key is used to encrypt and decrypt documents. It **must** be 32 bytes (64 hex characters).

```bash
openssl rand -hex 32
```
*Copy the output for use in the `.env` file.*

### 2. Generate TLS Certificates
The server runs over HTTPS. Generate a self-signed certificate for local development:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
```

### 3. Configure Environment Variables
Create a `.env` file in the project root:

```env
# Mandatory: 32-byte hex key for document encryption
MASTER_KEY=your_generated_64_character_hex_key

# Optional: Server configuration (defaults shown)
PORTNUM=3000
CERTFILE=cert.pem
KEYFILE=key.pem
```

## Compilation and Running

### Build the Project
To compile the project and its dependencies:

```bash
cargo build
```

### Run the Server
To start the server in development mode:

```bash
cargo run
```
The server will be available at `https://localhost:PORTNUM`. where PORTNUM is either 3000 by default or by the port number described in `.env`

### Run Tests
To execute the automated test suite:

```bash
cargo test
```

## Project Structure

- `src/main.rs`: Application entry point and router configuration.
- `src/users.rs`: User management, hashing, and authentication logic.
- `src/documents.rs`: Document metadata management and storage logic.
- `src/sessions.rs`: Thread-safe session management.
- `src/log.rs`: Multi-target logging configuration (security, access, and general logs).
- `static/`: Frontend JavaScript and static assets.
- `templates/`: HTML templates for the user interface.
- `data/`: Persistent storage for users, metadata, and encrypted files.

## Security Implementation

- **Encryption**: Files are encrypted on upload using AES-256-GCM before being written to disk.
- **XSS Protection**: Externalized JavaScript and a strict Content Security Policy (CSP) that forbids inline scripts.
- **Brute Force Protection**: Account locking after 5 failed login attempts and request rate-limiting on sensitive endpoints.
- **Session Security**: Cookies are flagged as `HttpOnly`, `Secure`, and `SameSite=Strict`.
