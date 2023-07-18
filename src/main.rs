use tide::prelude::*;
use tide::Request;

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut app = tide::new();
    app.at("/calendar/:id").get(get_calendar);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

async fn get_calendar(req: Request<()>) -> tide::Result {
    let id = req.param("id")?;
    let calendar = json!({
        "id": id,
        "start": "2023-01-01",
        "end": "2023-12-31",
        "events":[
            {
                "id": "1",
                "name": "New Year's Day",
                "date": "2023-01-01"
            },
            {
                "id": "2",
                "name": "Buy new car",
                "date": "2023-02-16"
            }
        ]
    });
    Ok(calendar.into())
}
