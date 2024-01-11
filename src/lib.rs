use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::StatusCode;
use actix_web::{
    delete, get, middleware::Logger, post, put, web, App, HttpRequest, HttpResponse, HttpServer,
    ResponseError,
};
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Local, Utc};
use chrono_tz::Tz;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{error, info};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::fmt::Debug;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs::File, io::BufReader};

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    habit: String,
    date_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum HabitState {
    Pending,
    Done,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseHabit {
    name: String,
    state: HabitState,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseHabitDetails {
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InputHabit {
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwt {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateUser {
    username: String,
    password: String,
    time_zone: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginUser {
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
    #[error("Not found")]
    NotFound(#[source] anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl ResponseError for CustomError {
    fn status_code(&self) -> StatusCode {
        match self {
            CustomError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            CustomError::AuthError(_) => StatusCode::UNAUTHORIZED,
            CustomError::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

pub fn run(tcp_listener: TcpListener, conn: Connection) -> Result<Server, std::io::Error> {
    if env::var("CALENDAR_IS_PROD_ENV").is_ok() && env::var("CALENDAR_JWT_SIGNING_KEY").is_err() {
        panic!("Cannot start Calendar Backend in PROD ENV without JWT signing key");
    }

    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("info"));

    let result: Option<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        .unwrap()
        .query_row([], |row| row.get(0))
        .optional()
        .unwrap();

    if result.is_none() {
        conn.execute(
            "CREATE TABLE event (
            id          INTEGER PRIMARY KEY,
            habit_id    INTEGER NOT NULL,
            date_time   TEXT NOT NULL,
            FOREIGN KEY (habit_id) REFERENCES habit (id) ON DELETE CASCADE ON UPDATE CASCADE
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE habit (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL,
            username    TEXT NOT NULL,
            UNIQUE(username, name),
            FOREIGN KEY (username) REFERENCES user (username) ON DELETE CASCADE ON UPDATE CASCADE
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE user (
            username       TEXT PRIMARY KEY,
            password_hash  TEXT NOT NULL,
            time_zone      TEXT NOT NULL
        )",
            (),
        )
        .unwrap();
    }

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
            .allowed_methods(vec!["GET", "POST", "DELETE", "PUT"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
            ])
            .max_age(3600);

        if env::var("CALENDAR_IS_PROD_ENV").is_err() {
            cors = cors.allowed_origin("http://localhost:3000")
        }

        App::new()
            .app_data(web::Data::clone(&data))
            .wrap(Logger::default())
            .wrap(cors)
            .service(create_event)
            .service(delete_event)
            .service(get_calendar)
            .service(create_user)
            .service(create_habit)
            .service(delete_habit)
            .service(edit_habit)
            .service(get_habit)
            .service(get_habit_details)
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
    info!("Create new event");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result: Option<i64> = conn
        .query_row_and_then(
            "SELECT id FROM habit WHERE username=?1 AND name=?2",
            (username.clone(), event.habit.clone()),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if result.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let result = conn.execute(
        "INSERT INTO event (habit_id, date_time) VALUES (?1, ?2)",
        (result, &event.date_time),
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

#[delete("/event")]
async fn delete_event(
    req: HttpRequest,
    event: web::Json<Event>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Delete event");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result: Option<i64> = conn
        .query_row_and_then(
            "SELECT id FROM habit WHERE username=?1 AND name=?2",
            (username.clone(), event.habit.clone()),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if result.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let result = conn.execute(
        "DELETE FROM event WHERE id = (SELECT id FROM event WHERE habit_id=?1 AND date_time=?2 LIMIT 1)",
        (result, &event.date_time),
    );
    match result {
        Ok(_) => {
            info!("deleted event");
        }
        Err(e) => {
            info!("error deleting event: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the event"
            )));
        }
    }
    Ok(HttpResponse::Ok().finish())
}

#[post("/habit")]
async fn create_habit(
    req: HttpRequest,
    habit: web::Json<InputHabit>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Create new habit");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let result = conn.execute(
        "INSERT INTO habit (username, name, description) VALUES (?1, ?2, ?3)",
        (&username, &habit.name, &habit.description),
    );
    match result {
        Ok(_) => {
            info!("created habit");
        }
        Err(e) => {
            info!("error creating habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when creating the habit"
            )));
        }
    }
    Ok(HttpResponse::Created().finish())
}

#[delete("/habit/{habit}")]
async fn delete_habit(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Delete habit");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    let habit = path.into_inner();

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let tx = conn.transaction().unwrap();

    let habit_id: Option<i64> = tx
        .query_row_and_then(
            "SELECT id FROM habit WHERE username=?1 AND name=?2",
            (username.clone(), &habit),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let result = tx.execute("DELETE FROM event WHERE habit_id=?1", [habit_id.unwrap()]);
    match result {
        Ok(_) => {
            info!("deleted habit events");
        }
        Err(e) => {
            info!("error deleting habit events: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the habit events"
            )));
        }
    }

    let result = tx.execute(
        "DELETE FROM habit WHERE username=?1 AND name=?2",
        (&username, &habit),
    );
    match result {
        Ok(_) => {
            info!("deleted habit");
        }
        Err(e) => {
            info!("error deleting habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the habit"
            )));
        }
    }
    let result = tx.commit();

    match result {
        Ok(_) => {
            info!("successfully commited the transaction");
        }
        Err(e) => {
            error!("error commiting the transaction: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when commiting delete habit transaction"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[put("/habit/{habit}")]
async fn edit_habit(
    req: HttpRequest,
    new_habit: web::Json<InputHabit>,
    path: web::Path<String>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Edit habit");
    let habit = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result = conn.execute(
        "UPDATE habit SET name=?1, description=?2 WHERE username=?3 AND name=?4",
        (&new_habit.name, &new_habit.description, &username, &habit),
    );
    match result {
        Ok(updated) => {
            if updated == 0 {
                info!("error editing habit, habit not found");
                return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
            }
            info!("edited habit");
        }
        Err(e) => {
            info!("error editing habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when editing the habit"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[get("/habit")]
async fn get_habit(req: HttpRequest, state: web::Data<State>) -> Result<HttpResponse, CustomError> {
    info!("Get habits");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn
        .prepare("SELECT h.name, max(e.date_time), u.time_zone 
                  FROM habit h LEFT JOIN event e ON h.id = e.habit_id JOIN user u ON h.username = u.username 
                  WHERE h.username = ?1 
                  GROUP BY h.id")
        .unwrap();

    let habit_iter = stmt
        .query_map([username.as_str()], |row| {
            let habit_name: String = row.get(0)?;
            let state = match row.get::<usize, String>(1) {
                Ok(latest_event_date) => {
                    let tz: Tz = row.get::<usize, String>(2)?.parse().unwrap();
                    let local_time = Local::now();
                    let user_time = local_time.with_timezone(&tz).date_naive();

                    let event_time = latest_event_date.parse::<DateTime<Utc>>().unwrap();
                    let event_time_in_user_time = event_time.with_timezone(&tz).date_naive();
                    if user_time == event_time_in_user_time {
                        HabitState::Done
                    } else {
                        HabitState::Pending
                    }
                }
                Err(_) => HabitState::Pending,
            };
            Ok(ResponseHabit {
                name: habit_name,
                state,
            })
        })
        .unwrap();

    let mut habits = Vec::new();
    for habit in habit_iter {
        habits.push(habit.unwrap());
    }

    Ok(HttpResponse::Ok().json(habits))
}

#[get("/habit/{habit}")]
async fn get_habit_details(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Get habit details");
    let habit = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let result: Option<(String, String)> = conn
        .query_row_and_then(
            "SELECT name, description FROM habit WHERE username=?1 AND name=?2",
            (username.clone(), habit.clone()),
            |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())),
        )
        .optional()
        .unwrap();

    if result.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let (habit_name, habit_description) = result.unwrap();

    Ok(HttpResponse::Ok().json(ResponseHabitDetails {
        name: habit_name,
        description: habit_description,
    }))
}

#[get("/calendar/{habit}")]
async fn get_calendar(
    path: web::Path<String>,
    state: web::Data<State>,
    req: HttpRequest,
) -> Result<HttpResponse, CustomError> {
    let habit = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    info!("Get calendar for habit = {} and user = {}", habit, username);

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result: Option<i64> = conn
        .query_row_and_then(
            "SELECT id FROM habit WHERE username=?1 AND name=?2",
            (username.clone(), habit.clone()),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if result.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let mut stmt = conn
        .prepare("SELECT date_time FROM event WHERE habit_id = ?1")
        .unwrap();

    let event_iter = stmt
        .query_map([result.unwrap()], |row| {
            Ok(Event {
                habit: habit.clone(),
                date_time: row.get(0)?,
            })
        })
        .unwrap();

    let mut events = Vec::new();
    for event in event_iter {
        events.push(event.unwrap());
    }

    Ok(HttpResponse::Ok().json(Calendar { events }))
}

#[post("/user")]
async fn create_user(
    user: web::Json<CreateUser>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Create new user");
    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let password_hash = hash(&user.password);
    let result = conn.execute(
        "INSERT INTO user (username, password_hash, time_zone) VALUES (?1, ?2, ?3)",
        (&user.username, &password_hash, &user.time_zone),
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

    Ok(HttpResponse::Created().json(Jwt {
        token: generate_jwt(user.username.clone())?,
    }))
}

#[post("/login")]
async fn login(
    user: web::Json<LoginUser>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Login user");
    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let credentials = Credentials {
        username: user.username.clone(),
        password: user.password.parse().unwrap(),
    };
    validate_credentials(credentials, conn).await?;

    Ok(HttpResponse::Ok().json(Jwt {
        token: generate_jwt(user.username.clone())?,
    }))
}

fn generate_jwt(username: String) -> Result<String, CustomError> {
    const ONE_MONTH: Duration = Duration::new(60 * 60 * 24 * 31, 0);
    let token_exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + ONE_MONTH;
    let my_claims = Claims {
        sub: username.clone(),
        exp: usize::try_from(token_exp.as_secs()).unwrap(),
    };
    let token = match encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(get_jwt_key().as_bytes()),
    ) {
        Ok(t) => t,
        Err(err) => {
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Could not generate JWT {}",
                err
            )))
        }
    };

    Ok(token)
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

fn authenticate(headers: &HeaderMap) -> Result<String, anyhow::Error> {
    let header_value = headers
        .get("Authorization")
        .context("The 'Authorization' header was missing")?
        .to_str()
        .context("The 'Authorization' header was not a valid UTF8 string.")?;
    let jwt = header_value
        .strip_prefix("Bearer ")
        .context("The authorization scheme was not 'Bearer'.")?;

    let token_data = match decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(get_jwt_key().as_bytes()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(err) => {
            error!("err {:?}", err);
            return Err(anyhow::anyhow!("Invalid token: {}", err));
        }
    };

    Ok(token_data.claims.sub)
}

async fn validate_credentials(
    credentials: Credentials,
    conn: &Connection,
) -> Result<(), CustomError> {
    let mut stmt = conn
        .prepare("SELECT password_hash FROM user WHERE username = ?1")
        .unwrap();

    let password_hash: Option<String> = stmt
        .query_row([credentials.username.as_str()], |row| row.get(0))
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

fn get_jwt_key() -> String {
    env::var("CALENDAR_JWT_SIGNING_KEY").unwrap_or(String::from("secret"))
}
