use futures::stream::TryStreamExt;
use log::info;
use mongodb::bson::doc;
use mongodb::options::ClientOptions;
use mongodb::Client;
use tide::prelude::*;
use tide::Request;

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    name: String,
    calendar_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    id: String,
    start: String,
    end: String,
    events: Vec<Event>,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    env_logger::init();
    info!("starting up");
    let mut app = tide::new();
    app.at("/calendar/:id").get(get_calendar);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

async fn get_calendar(req: Request<()>) -> tide::Result {
    let id = req.param("id")?;

    info!("getting calendar for {}", id);

    let client = Client::with_options(ClientOptions::parse("mongodb://localhost:27017").await?)?;
    let db = client.database("calendar");

    for collection_name in db.list_collection_names(None).await? {
        info!("collection {}", collection_name);
    }

    info!("executing db find() query");

    let events_collection = db.collection::<Event>("events");
    let filter = doc! { "calendar_id": id };
    let mut cursor = events_collection.find(filter, None).await?;
    let mut events = Vec::new();
    while let Some(event) = cursor.try_next().await? {
        events.push(event);
    }

    let calendar = Calendar {
        id: id.to_string(),
        start: "2023-01-01".to_string(),
        end: "2023-12-31".to_string(),
        events,
    };

    Ok(serde_json::to_string(&calendar)?.into())
}
