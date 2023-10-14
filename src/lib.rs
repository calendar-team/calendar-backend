use std::convert::TryFrom;
use std::time::{UNIX_EPOCH, SystemTime, Duration};
use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::StatusCode;
use actix_web::{
    get, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine;
use log::info;
use regex::Regex;
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
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    name: String,
    // #[serde(with = "mongodb::bson::serde_helpers::bson_datetime_as_rfc3339_string")]
    date_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwt{
    token: String,
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
            username    TEXT NOT NULL,
            name        TEXT NOT NULL,
            date_time   TEXT NOT NULL
        )",
        (),
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE user (
            username       TEXT PRIMARY KEY,
            password_hash  TEXT NOT NULL
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
        let vercel_origin: Regex =
            Regex::new(r"^https://calendar-frontend-.*\.vercel\.app$").unwrap();
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

    let username = basic_authentication(req.headers()).map_err(CustomError::AuthError)?;

    let result = conn.execute(
        "INSERT INTO event (username, name, date_time) VALUES (?1, ?2, ?3)",
        (&username, &event.name, &event.date_time),
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
async fn create_user(
    user: web::Json<User>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let password_hash = hash(&user.password);

    let result = conn.execute(
        "INSERT INTO user (username, password_hash) VALUES (?1, ?2)",
        (&user.username, &password_hash),
    );
    match result {
        Ok(_) => {
            info!("inserted user");
        }
        Err(u) => {
            info!("error inserting user: {}", u);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when saving the user"
            )));
        }
    }

    let jwt = Jwt { token: generate_jwt(user.username.clone()) };

    Ok(HttpResponse::Created().json(jwt))
}

#[post("/login")]
async fn login(
    user: web::Json<User>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let credentials = Credentials {
        username: user.username.clone(),
        password: user.password.parse().unwrap(),
    };
    validate_credentials(credentials, conn).await?;

    let jwt = Jwt { token: generate_jwt(user.username.clone()) };

    Ok(HttpResponse::Ok().json(jwt))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn generate_jwt(username : String) -> String{
    
    let key = b"secret";

    const ONE_WEEK: Duration = Duration::new(7*24*60*60, 0);
    let token_exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + ONE_WEEK;
    let my_claims = Claims {
        sub: username.clone(),
        exp: usize::try_from(token_exp.as_secs()).unwrap(),
    };
    let token = match encode(&Header::default(), &my_claims, &EncodingKey::from_secret(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };

    info!("token {}", token);

    token
}

fn load_rustls_config() -> ServerConfig {
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

fn basic_authentication(headers: &HeaderMap) -> Result<String, anyhow::Error> {
    // The header value, if present, must be a valid UTF8 string
    let header_value = headers
        .get("Authorization")
        .context("The 'Authorization' header was missing")?
        .to_str()
        .context("The 'Authorization' header was not a valid UTF8 string.")?;
    let base64encoded_segment = header_value
        .strip_prefix("Bearer ")
        .context("The authorization scheme was not 'Bearer'.")?;
    let key = b"secret";

    let token_data = match decode::<Claims>(&base64encoded_segment, &DecodingKey::from_secret(key), &Validation::new(Algorithm::HS256)) {
        Ok(c) => c,
        Err(err) => {
            info!("err {}", err);
            panic!("Some other errors")
        },
    };
    info!("decoded token data {:?}", token_data);

    Ok(token_data.claims.sub)
}

async fn validate_credentials(
    credentials: Credentials,
    conn: &Connection,
) -> Result<(), CustomError> {
    info!("validating credentials for {}", credentials.username);

    let mut stmt = conn
        .prepare("SELECT password_hash FROM user WHERE username = ?1")
        .unwrap();

    let password_hash: Option<String> = stmt
        .query_row(&[credentials.username.as_str()], |row| row.get(0))
        .optional()
        .unwrap();

    if password_hash.is_none() {
        return Err(CustomError::AuthError(anyhow::anyhow!(
            "Invalid username or password."
        )));
    }
    let password_hash = password_hash.unwrap();

    let expected_password = PasswordHash::new(&password_hash)
        .context("Failed to parse hash in PHC string format.")
        .map_err(CustomError::UnexpectedError)?;

    Argon2::default()
        .verify_password(
            credentials.password.expose_secret().as_bytes(),
            &expected_password,
        )
        .context("Invalid password.")
        .map_err(CustomError::AuthError)?;

    Ok(())
}

fn hash(password: &String) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());

    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}
