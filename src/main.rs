use log::info;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tide::http::headers::HeaderValue;
use tide::prelude::*;
use tide::security::{CorsMiddleware, Origin};
use tide::{Request, Response, StatusCode};

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

#[async_std::main]
async fn main() -> tide::Result<()> {
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

    app.at("/calendar/:id").get(get_calendar2);
    app.at("/event").post(create_event2);
    app.listen(
        tide_rustls::TlsListener::build().addrs("0.0.0.0:8080")
        .cert("/etc/letsencrypt/live/calendar.aguzovatii.com/cert.pem")
        .key("/etc/letsencrypt/live/calendar.aguzovatii.com/privkey.pem"),
    )
    .await?;
    Ok(())
}

async fn get_calendar2(req: Request<State>) -> tide::Result {
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

async fn create_event2(mut req: Request<State>) -> tide::Result {
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
