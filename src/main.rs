use std::{fs::File, io::BufReader};
use actix_cors::Cors;
use log::info;
use std::env;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tide::http::headers::HeaderValue;
use tide::prelude::*;
use tide::security::{CorsMiddleware, Origin};
use tide::{Request, Response, StatusCode};
use actix_web::{middleware::Logger, http, post, get, web, App, HttpServer, HttpResponse, Responder, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

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

#[post("/event")]
async fn create_event_2(event: web::Json<Event>, state: web::Data<State>) -> HttpResponse {
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
async fn get_calendar_2(id: web::Path<String>, state: web::Data<State>) -> HttpResponse{
    info!("getting calendar for {}", id);

    let mut stmt_result = (&state).conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn.prepare("SELECT name, calendar_id, date_time FROM event").unwrap();

    let event_iter = stmt.query_map([], |row| {
        Ok(Event {
            name: row.get(0)?,
            calendar_id: row.get(1)?,
            date_time: row.get(2)?,
        })
    }).unwrap();

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {

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
    ).unwrap();

    let state = State {
        conn: Arc::new(Mutex::new(conn)),
    };

    let data = web::Data::new(state);

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&data))
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .service(create_event_2)
            .service(get_calendar_2)
    });

    if env::var("CALENDAR_USE_TLS").is_ok() {
        server = server.bind_rustls_021("0.0.0.0:8080", load_rustls_config())?;
    } else {
        server = server.bind(("0.0.0.0", 8080))?;
    }

    server.run().await
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/fullchain.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/privkey.pem").unwrap());

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

// #[async_std::main]
async fn main2() -> tide::Result<()> {
    env_logger::init();
    info!("starting up");

    let conn = Connection::open_in_memory()?;

    conn.execute(
        "CREATE TABLE event (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL,
            calendar_id TEXT NOT NULL,
            date_time   TEXT NOT NULL
        )",
        (), // empty list of parameters.
    )?;

    let state = State {
        conn: Arc::new(Mutex::new(conn)),
    };

    let cors = CorsMiddleware::new()
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(state);
    app.with(cors);

    app.at("/calendar/:id").get(get_calendar);
    app.at("/event").post(create_event);

    if env::var("CALENDAR_USE_TLS").is_ok() {
        app.listen(
            tide_rustls::TlsListener::build().addrs("0.0.0.0:8080")
            .cert("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/fullchain.pem")
            .key("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/privkey.pem"),
        )
        .await?;
    } else {
        app.listen("0.0.0.0:8080").await?;
    }
    Ok(())
}

async fn get_calendar(req: Request<State>) -> tide::Result {
    let id = req.param("id")?;
    info!("getting calendar for {}", id);

    let mut stmt_result = req.state().conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn.prepare("SELECT name, calendar_id, date_time FROM event")?;

    let event_iter = stmt.query_map([], |row| {
        Ok(Event {
            name: row.get(0)?,
            calendar_id: row.get(1)?,
            date_time: row.get(2)?,
        })
    })?;

    let mut events = Vec::new();
    for event in event_iter {
        events.push(event.unwrap());
    }

    let calendar = Calendar {
        id: id.to_string(),
        events,
    };

    Ok(serde_json::to_string(&calendar)?.into())
}

async fn create_event(mut req: Request<State>) -> tide::Result {
    let event: tide::Result<Event> = req.body_json().await;

    match event {
        Ok(event) => {
            let mut stmt_result = req.state().conn.lock().expect("failed to lock conn");
            let conn = &mut *stmt_result;
            let result = conn.execute(
                "INSERT INTO event (name, calendar_id, date_time) VALUES (?1, ?2, ?3)",
                (event.name, event.calendar_id, event.date_time),
            );
            match result {
                Ok(_) => {
                    info!("inserted event");
                }
                Err(e) => {
                    info!("error inserting event: {}", e);
                    return Ok(Response::new(StatusCode::InternalServerError));
                }
            }
        }
        Err(e) => {
            info!("error parsing event: {}", e);
            return Ok(Response::new(StatusCode::BadRequest));
        }
    }
    Ok(Response::new(StatusCode::Created))
}
