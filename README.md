## Rust Role-Based Auth

A Rust library for **user authentication** and **role-based authorization (RBAC)** using a clean, modular design.  
It provides a focused core for managing users, verifying credentials, and enforcing role-based permissions that can be integrated into web services, CLIs, or backend systems.

### Features

- **User roles**: `Admin`, `Moderator`, `User`
- **Authentication**: username/password checks via an in-memory `UserStore`
- **Authorization**: role-based permission checks with a simple role hierarchy:
  - `Admin` > `Moderator` > `User`
- **Typed errors**: `AuthError` enum for clear failure cases
- **Unit tests**: examples for adding users, authenticating, and authorizing

---

## Project structure

- **`src/lib.rs`**  
  Exposes the public `auth` module: `pub mod auth;`.

- **`src/auth.rs`**  
  Core authentication / authorization logic:
  - `Role` – user role enum
  - `User` – user representation
  - `UserStore` – in-memory user storage
  - `AuthError` – error enum for auth failures
  - Unit tests under `#[cfg(test)]`.

- **`src/main.rs`**  
  Small CLI demo that:
  - adds sample users,
  - authenticates an admin user,
  - and attempts an admin-only action with a moderator.

---

## Getting started

### Prerequisites

- Rust (stable) and Cargo installed  
  You can install Rust via [`rustup`](https://rustup.rs).

### Run tests

```bash
cargo test
```

This runs the unit tests in the `auth` module, covering:

- Adding and authenticating a user
- Handling invalid passwords
- Enforcing the role hierarchy for authorization

### Build & run example

From the project root (where `Cargo.toml` lives), you can run the included binary to see:

- Registration of sample users with different roles
- Successful authentication for the `admin` user
- A failed authorization attempt where a `moderator` tries to perform an `Admin`-only action

---

## Usage as a library

You can depend on this crate in other Rust projects and use the `auth` module to manage users, authenticate credentials, and enforce role-based permissions. Typical integration points include:

- HTTP handlers in web services
- Middleware for protecting routes or operations
- CLI commands that require different permission levels

In a larger application, you would typically:

- Replace the in-memory `HashMap` with a database-backed store or external identity provider
- Store password **hashes** instead of plain text
- Integrate `authenticate` and `authorize` into HTTP handlers, middleware, or CLI commands

---

## License

This project is provided under an open license suitable for production and commercial use.  
Consult the `LICENSE` file for full details.
