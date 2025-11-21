use std::collections::HashMap;

/// Public roles a user can have in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Role {
    Admin,
    Moderator,
    User,
}

/// Basic user representation used for authentication & authorization.
#[derive(Debug, Clone)]
pub struct User {
    username: String,
    // In real applications you would store a password hash instead of the plain text.
    password: String,
    role: Role,
}

impl User {
    pub fn new(username: impl Into<String>, password: impl Into<String>, role: Role) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            role,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn role(&self) -> Role {
        self.role
    }

    fn check_password(&self, candidate: &str) -> bool {
        self.password == candidate
    }
}

/// Errors that can occur during authentication / authorization.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("user `{0}` already exists")]
    UserAlreadyExists(String),

    #[error("user `{0}` was not found")]
    UserNotFound(String),

    #[error("invalid password for user `{0}`")]
    InvalidPassword(String),

    #[error("user `{username}` is not allowed to perform action requiring role `{required:?}` (has `{actual:?}`)")]
    NotAuthorized {
        username: String,
        required: Role,
        actual: Role,
    },

    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
}

/// In‑memory store of all users.
///
/// This keeps the example simple and focuses on modules and basic design.
#[derive(Debug, Default)]
pub struct UserStore {
    users: HashMap<String, User>,
}

impl UserStore {
    /// Create an empty user store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new user. Fails if the username is already taken.
    pub fn add_user(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
        role: Role,
    ) -> Result<(), AuthError> {
        let username = username.into();
        let password = password.into();

        if self.users.contains_key(&username) {
            return Err(AuthError::UserAlreadyExists(username));
        }

        let user = User::new(username.clone(), password, role);
        self.users.insert(username, user);
        Ok(())
    }

    /// Try to authenticate a user by username and password.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<&User, AuthError> {
        let user = self
            .users
            .get(username)
            .ok_or_else(|| AuthError::UserNotFound(username.to_string()))?;

        if user.check_password(password) {
            Ok(user)
        } else {
            Err(AuthError::InvalidPassword(username.to_string()))
        }
    }

    /// Check if the given user has at least the required role.
    ///
    /// For simplicity we define the "power" order as Admin > Moderator > User.
    pub fn authorize(
        &self,
        username: &str,
        required: Role,
    ) -> Result<(), AuthError> {
        let user = self
            .users
            .get(username)
            .ok_or_else(|| AuthError::UserNotFound(username.to_string()))?;

        if has_required_role(user.role, required) {
            Ok(())
        } else {
            Err(AuthError::NotAuthorized {
                username: username.to_string(),
                required,
                actual: user.role,
            })
        }
    }
}

pub fn has_required_role(actual: Role, required: Role) -> bool {
    use Role::*;

    let rank = |r: Role| match r {
        User => 0,
        Moderator => 1,
        Admin => 2,
    };

    rank(actual) >= rank(required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_authenticate_user() {
        let mut store = UserStore::new();
        store
            .add_user("admin", "password", Role::Admin)
            .expect("failed to add user");

        let user = store
            .authenticate("admin", "password")
            .expect("authentication failed");
        assert_eq!(user.username(), "admin");
        assert_eq!(user.role(), Role::Admin);
    }

    #[test]
    fn reject_wrong_password() {
        let mut store = UserStore::new();
        store
            .add_user("user", "password", Role::User)
            .expect("failed to add user");

        let err = store
            .authenticate("user", "wrong")
            .expect_err("expected an error");
        matches!(err, AuthError::InvalidPassword(_));
    }

    #[test]
    fn authorize_based_on_role() {
        let mut store = UserStore::new();
        store
            .add_user("mod", "password", Role::Moderator)
            .expect("failed to add user");

        // Moderator can do User actions
        assert!(store.authorize("mod", Role::User).is_ok());
        // But not Admin actions
        assert!(store.authorize("mod", Role::Admin).is_err());
    }
}


