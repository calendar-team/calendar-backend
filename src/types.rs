use std::sync::{Arc, Mutex};

use rusqlite::Connection;

#[derive(Clone)]
pub struct State {
    pub conn: Arc<Mutex<Connection>>,
}
