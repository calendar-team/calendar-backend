use calendar_backend::run;
use rusqlite::Connection;
use std::net::TcpListener;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let db_path = "./database.db3";
    let conn = Connection::open(db_path).unwrap();

    let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind to port 8080");
    run(listener, conn)?.await
}
