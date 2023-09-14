use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::StatusCode;
use actix_web::{
    get, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Context;
use base64::Engine;
use log::info;
use rusqlite::{Connection, OptionalExtension};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::Debug;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::{fs::File, io::BufReader};
use regex::Regex;

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

struct Credentials {
    username: String,
    password: Secret<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CustomError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl ResponseError for CustomError {
    fn status_code(&self) -> StatusCode {
        match self {
            CustomError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // Return a 401 for auth errors
            CustomError::AuthError(_) => StatusCode::UNAUTHORIZED,
        }
    }
}

pub fn run(tcp_listener: TcpListener) -> Result<Server, std::io::Error> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("info"));
    let conn = Connection::open_in_memory().unwrap();

    conn.execute(
        "CREATE TABLE event (
            id          INTEGER PRIMARY KEY,
            user_id     INTEGER NOT NULL,
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
            username  TEXT NOT NULL UNIQUE,
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
        //defining this regex outside in order to avoid to recompile it on every request
        let vercel_origin: Regex = Regex::new(r"^https://calendar-frontend-.*\.vercel\.app$").unwrap();
        let mut cors = Cors::default()
            .allowed_origin("https://calendar.aguzovatii.com")
            .allowed_origin_fn(move |origin, _req_head|{
                let result = origin.to_str();
                match result {
                    Ok(origin) => {
                        vercel_origin.is_match(origin)
                    }
                    Err(_) => {
                        info!("CORS: Origin denied because it doesn't contain only visible ASCII chars.");
                        false
                    }
                }
            })
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
        server = server.listen_rustls_0_21(tcp_listener, load_rustls_config())?;
    } else {
        server = server.listen(tcp_listener)?;
    }

    Ok(server.run())
}

#[post("/event")]
async fn create_event(
    req: HttpRequest,
    event: web::Json<Event>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let credentials = basic_authentication(req.headers()).map_err(CustomError::AuthError)?;
    let user_id = validate_credentials(credentials, conn).await?;

    let result = conn.execute(
        "INSERT INTO event (user_id, username, name, date_time) VALUES (?1, ?2, ?3, ?4)",
        (&user_id, &event.username, &event.name, &event.date_time),
    );
    match result {
        Ok(_) => {
            info!("inserted event");
        }
        Err(e) => {
            info!("error inserting event: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when saving the event"
            )));
        }
    }
    Ok(HttpResponse::Created().finish())
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

fn basic_authentication(headers: &HeaderMap) -> Result<Credentials, anyhow::Error> {
    // The header value, if present, must be a valid UTF8 string
    let header_value = headers
        .get("Authorization")
        .context("The 'Authorization' header was missing")?
        .to_str()
        .context("The 'Authorization' header was not a valid UTF8 string.")?;
    let base64encoded_segment = header_value
        .strip_prefix("Basic ")
        .context("The authorization scheme was not 'Basic'.")?;
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64encoded_segment)
        .context("Failed to base64-decode 'Basic' credentials.")?;
    let decoded_credentials = String::from_utf8(decoded_bytes)
        .context("The decoded credential string is not valid UTF8.")?;
    // Split into two segments, using ':' as delimiter
    let mut credentials = decoded_credentials.splitn(2, ':');
    let username = credentials
        .next()
        .ok_or_else(|| anyhow::anyhow!("A username must be provided in 'Basic' auth."))?
        .to_string();
    let password = credentials
        .next()
        .ok_or_else(|| anyhow::anyhow!("A password must be provided in 'Basic' auth."))?
        .to_string();

    Ok(Credentials {
        username,
        password: Secret::new(password),
    })
}

async fn validate_credentials(
    credentials: Credentials,
    conn: &Connection,
) -> Result<i64, CustomError> {
    let mut stmt = conn
        .prepare("SELECT id FROM user WHERE username = ?1 and password = ?2")
        .unwrap();

    let id: Option<i64> = stmt
        .query_row(
            &[
                credentials.username.as_str(),
                credentials.password.expose_secret().as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    return id
        .ok_or_else(|| CustomError::AuthError(anyhow::anyhow!("Invalid username or password.")));
}
