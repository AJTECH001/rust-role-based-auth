use rusqlite::{params, Connection};
use rand_core::OsRng;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::auth::{AuthError, Role};

/// SQLite-backed user store.
///
/// This persists users in a `users` table with columns:
/// - `username` (TEXT PRIMARY KEY)
/// - `password` (TEXT NOT NULL)
/// - `role` (TEXT NOT NULL) – one of "Admin", "Moderator", "User"
pub struct DbUserStore {
    pub(crate) conn: Connection,
}

impl DbUserStore {
    /// Open (or create) a SQLite database at the given path and
    /// ensure the `users` table exists.
    pub fn new(db_path: &str) -> Result<Self, AuthError> {
        let conn = Connection::open(db_path).map_err(AuthError::DatabaseError)?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role     TEXT NOT NULL
            );
            "#,
        )
        .map_err(AuthError::DatabaseError)?;

        Ok(Self { conn })
    }

    /// Register a new user. Fails if the username already exists.
    pub fn add_user(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<(), AuthError> {
        // Check if user already exists
        if self.user_exists(username)? {
            return Err(AuthError::UserAlreadyExists(username.to_string()));
        }

        // Hash the plaintext password before storing it.
        let password_hash = hash_password(password)
            .map_err(|_| AuthError::DatabaseError(rusqlite::Error::InvalidQuery))?;

        self.conn
            .execute(
                "INSERT INTO users (username, password, role) VALUES (?1, ?2, ?3)",
                params![username, password_hash, role_to_str(role)],
            )
            .map_err(AuthError::DatabaseError)?;

        Ok(())
    }

    /// Authenticate a user by username and password.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Role, AuthError> {
        let (stored_password_hash, stored_role): (String, String) = self
            .conn
            .query_row(
                "SELECT password, role FROM users WHERE username = ?1",
                params![username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AuthError::UserNotFound(username.to_string()))?;

        if !verify_password(&stored_password_hash, password) {
            return Err(AuthError::InvalidPassword(username.to_string()));
        }

        let role = str_to_role(&stored_role)
            .ok_or_else(|| AuthError::UserNotFound(username.to_string()))?;

        Ok(role)
    }

    /// Authorize the given user for an action requiring `required` role.
    pub fn authorize(
        &self,
        username: &str,
        required: Role,
    ) -> Result<(), AuthError> {
        let (_, stored_role_str): (String, String) = self
            .conn
            .query_row(
                "SELECT password, role FROM users WHERE username = ?1",
                params![username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AuthError::UserNotFound(username.to_string()))?;

        let actual_role = str_to_role(&stored_role_str)
            .ok_or_else(|| AuthError::UserNotFound(username.to_string()))?;

        if crate::auth::has_required_role(actual_role, required) {
            Ok(())
        } else {
            Err(AuthError::NotAuthorized {
                username: username.to_string(),
                required,
                actual: actual_role,
            })
        }
    }

    fn user_exists(&self, username: &str) -> Result<bool, AuthError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(1) FROM users WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .map_err(AuthError::DatabaseError)?;

        Ok(count > 0)
    }
}

fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

fn verify_password(stored_hash: &str, password: &str) -> bool {
    let parsed_hash = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn role_to_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "Admin",
        Role::Moderator => "Moderator",
        Role::User => "User",
    }
}

fn str_to_role(value: &str) -> Option<Role> {
    match value {
        "Admin" => Some(Role::Admin),
        "Moderator" => Some(Role::Moderator),
        "User" => Some(Role::User),
        _ => None,
    }
}


