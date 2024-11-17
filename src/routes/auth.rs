use actix_web::{post, web, HttpResponse, Responder};
use argon2::{self, Config};
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::{EntityTrait, Set};
use serde::{Deserialize, Serialize};

use crate::auth::Claims;
use crate::models::{users, users::Entity as Users};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
}

#[post("/login")]
async fn login(
    db: web::Data<sea_orm::DatabaseConnection>,
    login_req: web::Json<LoginRequest>,
    config: web::Data<crate::auth::Config>,
) -> impl Responder {
    let user = Users::find_by_username(&login_req.username)
        .one(db.get_ref())
        .await
        .expect("Failed to fetch user");

    match user {
        Some(user) => {
            if verify_password(&login_req.password, &user.password_hash) {
                let claims = Claims {
                    sub: user.username,
                    role: user.role,
                    exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(config.jwt_secret.as_ref()),
                )
                .expect("Failed to create token");

                HttpResponse::Ok().json(LoginResponse { token })
            } else {
                HttpResponse::Unauthorized().finish()
            }
        }
        None => HttpResponse::Unauthorized().finish(),
    }
}

fn verify_password(password: &str, hash: &str) -> bool {
    argon2::verify_encoded(hash, password.as_bytes()).unwrap_or(false)
}

pub fn auth_config() -> actix_web::Scope {
    web::scope("/auth").service(login)
}