use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::http::header;
use actix_web::{get, middleware::Logger, post, web, App, HttpResponse, HttpServer};
use log::info;
use rusqlite::Connection;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::{Arc, Mutex};
use std::{fs::File, io::BufReader};

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    username: String,
    name: String,
    // #[serde(with = "mongodb::bson::serde_helpers::bson_datetime_as_rfc3339_string")]
    date_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Clone)]
struct State {
    conn: Arc<Mutex<Connection>>,
}

pub fn run() -> Result<Server, std::io::Error> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let conn = Connection::open_in_memory().unwrap();

    conn.execute(
        "CREATE TABLE event (
            id          INTEGER PRIMARY KEY,
            username    TEXT NOT NULL,
            name        TEXT NOT NULL,
            date_time   TEXT NOT NULL
        )",
        (), // empty list of parameters.
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE user (
            id        INTEGER PRIMARY KEY,
            username  TEXT NOT NULL,
            password  TEXT NOT NULL
        )",
        (),
    )
    .unwrap();

    let state = State {
        conn: Arc::new(Mutex::new(conn)),
    };

    let data = web::Data::new(state);

    let mut server = HttpServer::new(move || {
        let mut cors = Cors::default()
            .allowed_origin("https://calendar.aguzovatii.com")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
            ])
            .max_age(3600);

        if !env::var("CALENDAR_IS_PROD_ENV").is_ok() {
            cors = cors.allowed_origin("http://localhost:3000")
        }

        App::new()
            .app_data(web::Data::clone(&data))
            .wrap(Logger::default())
            .wrap(cors)
            .service(create_event)
            .service(get_calendar)
            .service(create_user)
            .service(login)
    });

    if env::var("CALENDAR_IS_PROD_ENV").is_ok() {
        server = server.bind_rustls_021("0.0.0.0:8080", load_rustls_config())?;
    } else {
        server = server.bind(("0.0.0.0", 8080))?;
    }

    Ok(server.run())
}

#[post("/event")]
async fn create_event(event: web::Json<Event>, state: web::Data<State>) -> HttpResponse {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result = conn.execute(
        "INSERT INTO event (username, name, date_time) VALUES (?1, ?2, ?3)",
        (&event.username, &event.name, &event.date_time),
    );
    match result {
        Ok(_) => {
            info!("inserted event");
        }
        Err(e) => {
            info!("error inserting event: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    }
    HttpResponse::Created().finish()
}

#[get("/calendar/{username}")]
async fn get_calendar(username: web::Path<String>, state: web::Data<State>) -> HttpResponse {
    info!("getting calendar for {}", username);

    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn
        .prepare("SELECT name, date_time FROM event WHERE username = ?1")
        .unwrap();

    let event_iter = stmt
        .query_map(&[username.as_str()], |row| {
            Ok(Event {
                username: username.to_string(),
                name: row.get(0)?,
                date_time: row.get(1)?,
            })
        })
        .unwrap();

    let mut events = Vec::new();
    for event in event_iter {
        events.push(event.unwrap());
    }

    let calendar = Calendar { events };

    HttpResponse::Ok().json(calendar)
}

#[post("/user")]
async fn create_user(user: web::Json<User>, state: web::Data<State>) -> HttpResponse {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result = conn.execute(
        "INSERT INTO user (username, password) VALUES (?1, ?2)",
        (&user.username, &user.password),
    );
    match result {
        Ok(_) => {
            info!("inserted user");
        }
        Err(u) => {
            info!("error inserting user: {}", u);
            return HttpResponse::InternalServerError().finish();
        }
    }
    HttpResponse::Created().finish()
}

#[post("/login")]
async fn login(user: web::Json<User>, state: web::Data<State>) -> HttpResponse {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let mut stmt = conn
        .prepare("SELECT COUNT(username) FROM user WHERE username = ?1 and password = ?2")
        .unwrap();

    let count: i64 = stmt
        .query_row(&[user.username.as_str(), user.password.as_str()], |row| {
            row.get(0)
        })
        .unwrap();

    if count == 1 {
        return HttpResponse::Ok().finish();
    }
    HttpResponse::Unauthorized().finish()
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(
        File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/fullchain.pem").unwrap(),
    );
    let key_file = &mut BufReader::new(
        File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/privkey.pem").unwrap(),
    );

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}
