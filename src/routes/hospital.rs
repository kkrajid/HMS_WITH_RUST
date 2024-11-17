use actix_web::{get, web, HttpResponse, Responder};
use actix_web_httpauth::middleware::HttpAuthentication;

use crate::auth::{validator, Claims};

#[get("/patients")]
async fn get_patients(claims: web::ReqData<Claims>) -> impl Responder {
    if claims.role == "doctor" || claims.role == "nurse" {
        HttpResponse::Ok().body("List of patients")
    } else {
        HttpResponse::Forbidden().body("Access denied")
    }
}

#[get("/prescriptions")]
async fn get_prescriptions(claims: web::ReqData<Claims>) -> impl Responder {
    if claims.role == "doctor" {
        HttpResponse::Ok().body("List of prescriptions")
    } else {
        HttpResponse::Forbidden().body("Access denied")
    }
}

#[get("/appointments")]
async fn get_appointments(claims: web::ReqData<Claims>) -> impl Responder {
    HttpResponse::Ok().body("List of appointments")
}

pub fn hospital_config() -> actix_web::Scope {
    web::scope("/hospital")
        .wrap(HttpAuthentication::bearer(validator))
        .service(get_patients)
        .service(get_prescriptions)
        .service(get_appointments)
}