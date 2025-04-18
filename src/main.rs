use chrono::Utc;
use rusqlite::Connection;
use std::{
    env,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let db_path = env::var("CALENDAR_DB_PATH").unwrap_or("./database.db3".to_string());
    let conn = Connection::open(db_path).unwrap();
    rusqlite::vtab::array::load_module(&conn).unwrap();
    let state = calendar_backend_lib::types::State {
        conn: Arc::new(Mutex::new(conn)),
        utc_now: Utc::now,
    };

    let cloned_state = state.clone();
    let task_scheduler = tokio::spawn(async {
        calendar_backend_lib::scheduler::start_task_scheduler(cloned_state).await
    });

    let listener = TcpListener::bind("[::]:8080").expect("Failed to bind to port 8080");
    let server = calendar_backend_lib::run(listener, state)?;
    select! {
        _ = server => {
            Ok(())
        }
        _ = task_scheduler => {
            Ok(())
        }
    }
}
