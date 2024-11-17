use actix_web::{web, App, HttpServer};
use sea_orm::Database;

mod auth;
mod models;
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = Database::connect(&database_url).await.expect("Failed to connect to database");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(routes::auth::auth_config())
            .service(routes::hospital::hospital_config())
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}