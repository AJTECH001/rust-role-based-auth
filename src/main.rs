use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use authorization::auth::{AuthError, Role};
use authorization::auth_db::DbUserStore;

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<DbUserStore>>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    username: String,
    role: Role,
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    username: String,
    required: String,
}

#[tokio::main]
async fn main() {
    // Use a real SQLite database file for persistence.
    let store =
        DbUserStore::new("auth.db").expect("failed to open or initialize database");

    let state = AppState {
        store: Arc::new(Mutex::new(store)),
    };

    // Allow cross-origin requests (CORS) from the frontend during development.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/authorize", get(authorize))
        .with_state(state)
        .layer(cors);

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    println!("HTTP server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind address");

    axum::serve(listener, app)
        .await
        .expect("server error");
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let role = parse_role(&body.role)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid role".to_string()))?;

    let store = state.store.lock().expect("mutex poisoned");
    store
        .add_user(&body.username, &body.password, role)
        .map_err(map_auth_error)?;

    Ok(StatusCode::CREATED)
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let store = state.store.lock().expect("mutex poisoned");
    let role = store
        .authenticate(&body.username, &body.password)
        .map_err(map_auth_error)?;

    Ok(Json(LoginResponse {
        username: body.username,
        role,
    }))
}

async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let required = parse_role(&query.required)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid required role".to_string()))?;

    let store = state.store.lock().expect("mutex poisoned");
    store
        .authorize(&query.username, required)
        .map_err(map_auth_error)?;

    Ok(StatusCode::OK)
}

fn parse_role(value: &str) -> Option<Role> {
    match value {
        "Admin" | "admin" => Some(Role::Admin),
        "Moderator" | "moderator" => Some(Role::Moderator),
        "User" | "user" => Some(Role::User),
        _ => None,
    }
}

fn map_auth_error(err: AuthError) -> (StatusCode, String) {
    match err {
        AuthError::UserAlreadyExists(_) => (StatusCode::CONFLICT, err.to_string()),
        AuthError::UserNotFound(_) | AuthError::InvalidPassword(_) => {
            (StatusCode::UNAUTHORIZED, err.to_string())
        }
        AuthError::NotAuthorized { .. } => (StatusCode::FORBIDDEN, err.to_string()),
        AuthError::DatabaseError(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string())
        }
    }
}

