use calendar_backend::run;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    run()?.await
}

