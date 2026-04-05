// Fixture: Rust web application with various frameworks and patterns

use actix_web::{web, App, HttpServer, HttpResponse};
use axum::{Router, routing::get};
use serde::Deserialize;
use crate::models::User;
use super::db;

mod handlers;
mod middleware;

// -- Actix-web attribute routes --

#[get("/users")]
async fn list_users() -> HttpResponse {
    HttpResponse::Ok().json(vec!["alice", "bob"])
}

#[post("/users")]
async fn create_user(body: web::Json<User>) -> HttpResponse {
    HttpResponse::Created().json(body.into_inner())
}

#[get("/users/{id}")]
async fn get_user(path: web::Path<u32>) -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[delete("/users/{id}")]
async fn delete_user(path: web::Path<u32>) -> HttpResponse {
    HttpResponse::NoContent().finish()
}

// -- Actix web::resource style --

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/health").route(web::get().to(health_check)));
}

// -- Axum style routes --

fn axum_router() -> Router {
    Router::new()
        .route("/api/items", get(list_items))
        .route("/api/items", post(create_item))
        .route("/api/items/:id", get(get_item))
}

// -- Environment variable usage --

fn setup_database() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let log_level = env::var("RUST_LOG").unwrap_or("info".to_string());
    let manifest = env!("CARGO_MANIFEST_DIR");
    let optional_key = option_env!("OPTIONAL_API_KEY");
    let secret = dotenvy::var("DOTENVY_SECRET").unwrap();
    let cache_url = std::env::var_os("CACHE_URL");
}

// -- Database write patterns --

async fn insert_record(pool: &PgPool) {
    sqlx::query!("INSERT INTO orders (user_id, total) VALUES ($1, $2)", user_id, total)
        .execute(pool)
        .await
        .unwrap();

    diesel::insert_into(products)
        .values(&new_product)
        .execute(conn)
        .unwrap();

    client.execute("UPDATE accounts SET balance = $1 WHERE id = $2", &[&balance, &id])
        .await
        .unwrap();

    conn.execute("DELETE FROM sessions WHERE expired_at < NOW()", &[])
        .await
        .unwrap();
}

// -- Hardcoded credential (should be detected) --

const DB_PASSWORD: &str = "super_secret_password_123";
let password = "hardcoded_pass_456";

// -- This should NOT be flagged (env var reference) --
let safe_password = env::var("DB_PASSWORD").unwrap();
