use actix_cors::Cors;
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
    name: String,
    calendar_id: String,
    // #[serde(with = "mongodb::bson::serde_helpers::bson_datetime_as_rfc3339_string")]
    date_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    id: String,
    events: Vec<Event>,
}

#[derive(Clone)]
struct State {
    conn: Arc<Mutex<Connection>>,
}

pub async fn run() -> std::io::Result<()> {

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let conn = Connection::open_in_memory().unwrap();

    conn.execute(
        "CREATE TABLE event (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL,
            calendar_id TEXT NOT NULL,
            date_time   TEXT NOT NULL
        )",
        (), // empty list of parameters.
    )
        .unwrap();

    let state = State {
        conn: Arc::new(Mutex::new(conn)),
    };

    let data = web::Data::new(state);

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&data))
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .service(create_event)
            .service(get_calendar)
    });

    if env::var("CALENDAR_USE_TLS").is_ok() {
        server = server.bind_rustls_021("0.0.0.0:8080", load_rustls_config())?;
    } else {
        server = server.bind(("0.0.0.0", 8080))?;
    }

    server.run().await
}


#[post("/event")]
async fn create_event(event: web::Json<Event>, state: web::Data<State>) -> HttpResponse {
    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result = conn.execute(
        "INSERT INTO event (name, calendar_id, date_time) VALUES (?1, ?2, ?3)",
        (&event.name, &event.calendar_id, &event.date_time),
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

#[get("/calendar/{id}")]
async fn get_calendar(id: web::Path<String>, state: web::Data<State>) -> HttpResponse {
    info!("getting calendar for {}", id);

    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn
        .prepare("SELECT name, calendar_id, date_time FROM event")
        .unwrap();

    let event_iter = stmt
        .query_map([], |row| {
            Ok(Event {
                name: row.get(0)?,
                calendar_id: row.get(1)?,
                date_time: row.get(2)?,
            })
        })
        .unwrap();

    let mut events = Vec::new();
    for event in event_iter {
        events.push(event.unwrap());
    }

    let calendar = Calendar {
        id: id.to_string(),
        events,
    };

    HttpResponse::Ok().json(calendar)
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
