use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::Connection;

pub type UtcNowFn = fn() -> DateTime<Utc>;

#[derive(Clone)]
pub struct State {
    pub conn: Arc<Mutex<Connection>>,
    pub utc_now: UtcNowFn,
}
