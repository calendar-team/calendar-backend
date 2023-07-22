use futures::stream::TryStreamExt;
use log::info;
use mongodb::bson::{DateTime, doc};
use mongodb::options::ClientOptions;
use mongodb::Client;
use tide::prelude::*;
use tide::{Request, Response, StatusCode};

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    name: String,
    calendar_id: String,
    #[serde(with = "mongodb::bson::serde_helpers::bson_datetime_as_rfc3339_string")]
    date_time: DateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    id: String,
    events: Vec<Event>,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    env_logger::init();
    info!("starting up");
    let mut app = tide::new();
    app.at("/calendar/:id").get(get_calendar);
    app.at("/event").post(create_event);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

async fn get_calendar(req: Request<()>) -> tide::Result {
    let id = req.param("id")?;
    info!("getting calendar for {}", id);
    let client = Client::with_options(ClientOptions::parse("mongodb://localhost:27017").await?)?;
    let db = client.database("calendar");
    let events_collection = db.collection::<Event>("events");
    let filter = doc! { "calendar_id": id };
    let mut cursor = events_collection.find(filter, None).await?;
    let mut events = Vec::new();
    loop {
        let event = cursor.try_next().await;
        match event {
            Ok(event) => match event {
                Some(event) => events.push(event),
                None => break,
            },
            Err(e) => {
                info!("error parsing event: {}", e);
                return Ok(Response::new(StatusCode::InternalServerError));
            }
        }
    }

    let calendar = Calendar {
        id: id.to_string(),
        events,
    };

    Ok(serde_json::to_string(&calendar)?.into())
}

async fn create_event(mut req: Request<()>) -> tide::Result {
    info!("inserting a new event in db");
    let client = Client::with_options(ClientOptions::parse("mongodb://localhost:27017").await?)?;
    let db = client.database("calendar");
    let events_collection = db.collection::<Event>("events");
    let event: tide::Result<Event> = req.body_json().await;
    match event {
        Ok(event) => {
            let result = events_collection.insert_one(event, None).await;
            match result {
                Ok(_) => {}
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
