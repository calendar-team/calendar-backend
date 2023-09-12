use calendar_backend::run;
use std::net::TcpListener;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("0.0.0.0:8080").expect("Failed to bind to port 8080");
    run(listener)?.await
}
