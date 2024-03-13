pub mod scheduler;
pub mod task;
pub mod types;

use crate::scheduler::schedule_tasks;
use crate::task::Recurrence;
use crate::task::RecurrenceType;
use crate::task::Task;
use crate::task::TaskDef;
use crate::task::TaskInput;
use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::StatusCode;
use actix_web::{
    delete, get, middleware::Logger, post, put, web, App, HttpRequest, HttpResponse, HttpServer,
    ResponseError,
};
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Local, Utc};
use chrono_tz::Tz;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{error, info};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension};
use rustls::ServerConfig;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::fmt::Debug;
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs::File, io::BufReader};
use types::State;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    date_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum HabitState {
    Pending,
    Done,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseHabit {
    id: String,
    name: String,
    state: HabitState,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseHabitDetails {
    id: String,
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InputHabit {
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Calendar {
    events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwt {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateUser {
    username: String,
    password: String,
    time_zone: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginUser {
    username: String,
    password: String,
}

struct Credentials {
    username: String,
    password: Secret<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CustomError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
    #[error("Not found")]
    NotFound(#[source] anyhow::Error),
    #[error("{{\"message\": \"{0}\"}}")]
    BadRequest(anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl ResponseError for CustomError {
    fn status_code(&self) -> StatusCode {
        match self {
            CustomError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            CustomError::AuthError(_) => StatusCode::UNAUTHORIZED,
            CustomError::NotFound(_) => StatusCode::NOT_FOUND,
            CustomError::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }
}

pub fn run(tcp_listener: TcpListener, state: State) -> Result<Server, std::io::Error> {
    if env::var("CALENDAR_IS_PROD_ENV").is_ok() && env::var("CALENDAR_JWT_SIGNING_KEY").is_err() {
        panic!("Cannot start Calendar Backend in PROD ENV without JWT signing key");
    }

    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("info"));

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result: Option<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        .unwrap()
        .query_row([], |row| row.get(0))
        .optional()
        .unwrap();

    if result.is_none() {
        conn.execute(
            "CREATE TABLE user (
            username       TEXT PRIMARY KEY,
            password_hash  TEXT NOT NULL,
            time_zone      TEXT NOT NULL
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE habit (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL,
            username    TEXT NOT NULL,
            UNIQUE(username, name),
            FOREIGN KEY (username) REFERENCES user (username) ON DELETE CASCADE ON UPDATE CASCADE
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE recurrence (
            id            TEXT PRIMARY KEY,
            type          TEXT NOT NULL,
            every         INTEGER NOT NULL,
            from_date     TEXT NOT NULL,
            on_week_days  TEXT,
            on_month_days TEXT
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE task_def (
            id            TEXT PRIMARY KEY,
            habit_id      TEXT NOT NULL,
            name          TEXT NOT NULL,
            description   TEXT NOT NULL,
            recurrence_id TEXT NOT NULL,
            FOREIGN KEY (habit_id) REFERENCES habit (id) ON DELETE CASCADE ON UPDATE CASCADE,
            FOREIGN KEY (recurrence_id) REFERENCES recurrence (id) ON DELETE CASCADE ON UPDATE CASCADE
        )",
            (),
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE task (
            id          TEXT PRIMARY KEY,
            task_def_id TEXT NOT NULL,
            state       TEXT NOT NULL,
            due_on      TEXT NOT NULL,
            done_on     TEXT,
            FOREIGN KEY (task_def_id) REFERENCES task_def (id) ON DELETE CASCADE ON UPDATE CASCADE
        )",
            (),
        )
        .unwrap();
    }

    drop(stmt_result);
    let data = web::Data::new(state);

    let mut server = HttpServer::new(move || {
        //defining this regex outside in order to avoid to recompile it on every request
        let vercel_origin: Regex =
            Regex::new(r"^https://calendar-frontend-.*\.vercel\.app$").unwrap();
        let mut cors = Cors::default()
            .allowed_origin("https://calendar.aguzovatii.com")
            .allowed_origin_fn(move |origin, _req_head|{
                let result = origin.to_str();
                match result {
                    Ok(origin) => {
                        vercel_origin.is_match(origin)
                    }
                    Err(_) => {
                        info!("CORS: Origin denied because it doesn't contain only visible ASCII chars.");
                        false
                    }
                }
            })
            .allowed_methods(vec!["GET", "POST", "DELETE", "PUT"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
            ])
            .max_age(3600);

        if env::var("CALENDAR_IS_PROD_ENV").is_err() {
            cors = cors.allowed_origin("http://localhost:3000")
        }

        App::new()
            .app_data(web::Data::clone(&data))
            .wrap(Logger::default())
            .wrap(cors)
            .service(create_user)
            .service(login)
            .service(create_habit)
            .service(delete_habit)
            .service(edit_habit)
            .service(get_all_habits)
            .service(get_habit_details)
            .service(get_tasks_defs)
            .service(create_task_def)
            .service(delete_task_def)
            .service(get_tasks)
            .service(complete_task)
    });

    if env::var("CALENDAR_IS_PROD_ENV").is_ok() {
        server = server.listen_rustls_0_22(tcp_listener, load_rustls_config())?;
    } else {
        server = server.listen(tcp_listener)?;
    }

    Ok(server.run())
}

#[post("/habit")]
async fn create_habit(
    req: HttpRequest,
    habit: web::Json<InputHabit>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Create new habit");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let habit_id = Uuid::new_v4();
    let result = conn.execute(
        "INSERT INTO habit (id, username, name, description) VALUES (?1, ?2, ?3, ?4)",
        (
            &habit_id.to_string(),
            &username,
            &habit.name,
            &habit.description,
        ),
    );
    match result {
        Ok(_) => {
            info!("created habit");
        }
        Err(e) => {
            info!("error creating habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when creating the habit"
            )));
        }
    }
    Ok(HttpResponse::Ok().json(ResponseHabitDetails {
        id: habit_id.to_string(),
        name: habit.name.clone(),
        description: habit.description.clone(),
    }))
}

#[delete("/habit/{habit_id}")]
async fn delete_habit(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Deleting the habit");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    let habit_id = path.into_inner();

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let tx = conn.transaction().unwrap();

    let habit_id: Option<String> = tx
        .query_row_and_then(
            "SELECT id FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let result = tx.execute(
        "DELETE FROM recurrence WHERE id in (SELECT recurrence_id FROM task_def WHERE habit_id=?1)",
        [&habit_id],
    );
    match result {
        Ok(_) => {
            info!("deleted tasks recurrences");
        }
        Err(e) => {
            info!("error deleting tasks recurrences: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the tasks recurrences"
            )));
        }
    }

    let result = tx.execute(
        "DELETE FROM task WHERE task_def_id in (SELECT id FROM task_def WHERE habit_id=?1)",
        [&habit_id],
    );
    match result {
        Ok(_) => {
            info!("deleted tasks");
        }
        Err(e) => {
            info!("error deleting tasks: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the tasks recurrences"
            )));
        }
    }

    let result = tx.execute("DELETE FROM task_def WHERE habit_id=?1", [&habit_id]);
    match result {
        Ok(_) => {
            info!("deleted tasks definitions");
        }
        Err(e) => {
            info!("error deleting tasks definitions: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the tasks definitions"
            )));
        }
    }

    let result = tx.execute("DELETE FROM habit WHERE id=?1", [&habit_id]);
    match result {
        Ok(_) => {
            info!("deleted habit");
        }
        Err(e) => {
            info!("error deleting habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the habit"
            )));
        }
    }
    let result = tx.commit();

    match result {
        Ok(_) => {
            info!("successfully commited the transaction");
        }
        Err(e) => {
            error!("error commiting the transaction: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when commiting delete habit transaction"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[put("/habit/{habit_id}")]
async fn edit_habit(
    req: HttpRequest,
    new_habit: web::Json<InputHabit>,
    path: web::Path<String>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Edit habit");
    let habit_id = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let result = conn.execute(
        "UPDATE habit SET name=?1, description=?2 WHERE id=?3 AND username=?4",
        (
            &new_habit.name,
            &new_habit.description,
            &habit_id,
            &username,
        ),
    );
    match result {
        Ok(updated) => {
            if updated == 0 {
                info!("error editing habit, habit not found");
                return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
            }
            info!("edited habit");
        }
        Err(e) => {
            info!("error editing habit: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when editing the habit"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[get("/habit")]
async fn get_all_habits(
    req: HttpRequest,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Get habits");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn
        .prepare("SELECT id, name FROM habit where username=?1")
        .unwrap();

    let habit_iter = stmt
        .query_map([username.as_str()], |row| {
            let habit_id: String = row.get(0)?;
            let habit_name: String = row.get(1)?;
            Ok(ResponseHabit {
                id: habit_id,
                name: habit_name,
                state: HabitState::Pending,
            })
        })
        .unwrap();

    let mut habits = Vec::new();
    for habit in habit_iter {
        habits.push(habit.unwrap());
    }

    Ok(HttpResponse::Ok().json(habits))
}

#[get("/habit")]
async fn get_all_habits2(
    req: HttpRequest,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Get habits");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let mut stmt = conn
        .prepare("SELECT h.id, h.name, max(e.date_time), u.time_zone 
                  FROM habit h LEFT JOIN event e ON h.id = e.habit_id JOIN user u ON h.username = u.username 
                  WHERE h.username = ?1 
                  GROUP BY h.id")
        .unwrap();

    let habit_iter = stmt
        .query_map([username.as_str()], |row| {
            let habit_id: String = row.get(0)?;
            let habit_name: String = row.get(1)?;
            let state = match row.get::<usize, String>(2) {
                Ok(latest_event_date) => {
                    let tz: Tz = row.get::<usize, String>(3)?.parse().unwrap();
                    let local_time = Local::now();
                    let user_time = local_time.with_timezone(&tz).date_naive();

                    let event_time = latest_event_date.parse::<DateTime<Utc>>().unwrap();
                    let event_time_in_user_time = event_time.with_timezone(&tz).date_naive();
                    if user_time == event_time_in_user_time {
                        HabitState::Done
                    } else {
                        HabitState::Pending
                    }
                }
                Err(_) => HabitState::Pending,
            };
            Ok(ResponseHabit {
                id: habit_id,
                name: habit_name,
                state,
            })
        })
        .unwrap();

    let mut habits = Vec::new();
    for habit in habit_iter {
        habits.push(habit.unwrap());
    }

    Ok(HttpResponse::Ok().json(habits))
}

#[get("/habit/{habit_id}")]
async fn get_habit_details(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Get habit details");
    let habit_id = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let result: Option<(String, String, String)> = conn
        .query_row_and_then(
            "SELECT id, name, description FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| {
                Ok((
                    row.get(0).unwrap(),
                    row.get(1).unwrap(),
                    row.get(2).unwrap(),
                ))
            },
        )
        .optional()
        .unwrap();

    if result.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let (habit_id, habit_name, habit_description) = result.unwrap();

    Ok(HttpResponse::Ok().json(ResponseHabitDetails {
        id: habit_id,
        name: habit_name,
        description: habit_description,
    }))
}

#[get("/habit/{habit_id}/tasks_defs")]
async fn get_tasks_defs(
    path: web::Path<String>,
    state: web::Data<State>,
    req: HttpRequest,
) -> Result<HttpResponse, CustomError> {
    let habit_id = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    info!(
        "Get tasks definitions for habit = {} and user = {}",
        habit_id, username
    );

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let habit_id: Option<String> = conn
        .query_row_and_then(
            "SELECT id FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let tasks_defs: Vec<TaskDef> = conn
        .prepare("SELECT t.id, t.name, t.description, r.type, r.every, r.from_date, r.on_week_days, r.on_month_days FROM task_def t JOIN recurrence r ON t.recurrence_id = r.id WHERE t.habit_id = ?1")
        .unwrap()
        .query_map([&habit_id], |row| {
            Ok(TaskDef{
                id: row.get(0).unwrap(),
                name: row.get(1).unwrap(),
                description: row.get(2).unwrap(),
                recurrence: Recurrence {
                    rec_type: row.get(3).unwrap(),
                    every: row.get(4).unwrap(),
                    from: row.get(5).unwrap(),
                    on_week_days: row.get(6).unwrap(),
                    on_month_days: row.get(7).unwrap(),
                }
            })
        })
        .unwrap()
        .map(|row| row.unwrap())
    .collect();

    Ok(HttpResponse::Ok().json(tasks_defs))
}

#[post("/habit/{habit_id}/tasks_defs")]
async fn create_task_def(
    req: HttpRequest,
    path: web::Path<String>,
    task_def: web::Json<TaskDef>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Create new task definition");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    let habit_id = path.into_inner();

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let tx = conn.transaction().unwrap();

    let habit_id: Option<String> = tx
        .query_row_and_then(
            "SELECT id FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    match task_def.recurrence.rec_type {
        RecurrenceType::Days => {
            if task_def.recurrence.on_week_days.is_some()
                || task_def.recurrence.on_month_days.is_some()
            {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "`Days` recurrence type does not allow selecting days of the week/mohth"
                )));
            }
        }
        RecurrenceType::Weeks => {
            if task_def.recurrence.on_week_days.is_none()
                || task_def
                    .recurrence
                    .on_week_days
                    .as_ref()
                    .unwrap()
                    .days
                    .is_empty()
            {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "At least one day of the week should be selected for `Weeks` recurrence type"
                )));
            }
            if task_def.recurrence.on_month_days.is_some() {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "`Weeks` recurrence type does not allow selecting days of the mohth"
                )));
            }
        }
        RecurrenceType::Months => {
            if task_def.recurrence.on_month_days.is_none()
                || task_def
                    .recurrence
                    .on_month_days
                    .as_ref()
                    .unwrap()
                    .days
                    .is_empty()
            {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "At least one day of the month should be selected for `Months` recurrence type"
                )));
            }
            if task_def.recurrence.on_week_days.is_some() {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "`Months` recurrence type does not allow selecting days of the week"
                )));
            }
        }
        RecurrenceType::Years => {
            if task_def.recurrence.on_week_days.is_some()
                || task_def.recurrence.on_month_days.is_some()
            {
                return Err(CustomError::BadRequest(anyhow::anyhow!(
                    "`Years` recurrence type does not allow selecting days of the week/mohth"
                )));
            }
        }
    }

    let recurrence_id = Uuid::new_v4();
    let task_def_id = Uuid::new_v4();
    let task_def = TaskDef {
        id: Some(task_def_id.to_string()),
        ..task_def.into_inner()
    };

    let result = tx.execute(
        "INSERT INTO recurrence (id, type, every, from_date, on_week_days, on_month_days) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (&recurrence_id.to_string(), &task_def.recurrence.rec_type, task_def.recurrence.every, &task_def.recurrence.from, &task_def.recurrence.on_week_days, &task_def.recurrence.on_month_days),
    );
    match result {
        Ok(_) => {
            info!("created recurrence for task definition");
        }
        Err(e) => {
            info!("error creating recurrence for task definition: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when creating the recurrence for task definition"
            )));
        }
    }

    let result = tx.execute(
        "INSERT INTO task_def (id, habit_id, name, description, recurrence_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        (&task_def.id, habit_id, &task_def.name, &task_def.description, recurrence_id.to_string()),
    );
    match result {
        Ok(_) => {
            info!("created task definition");
        }
        Err(e) => {
            info!("error creating task definition: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when creating the task definition"
            )));
        }
    }

    let tz: String = tx
        .query_row_and_then(
            "SELECT time_zone FROM user WHERE username=?1",
            [&username],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
        .unwrap();

    let tz = tz.parse().unwrap();
    schedule_tasks(&task_def, tz, &tx)?;

    let result = tx.commit();

    match result {
        Ok(_) => {
            info!("successfully commited the transaction");
        }
        Err(e) => {
            error!("error commiting the transaction: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when commiting create task definition transaction"
            )));
        }
    }

    Ok(HttpResponse::Created().finish())
}

#[delete("/habit/{habit_id}/tasks_defs/{task_id}")]
async fn delete_task_def(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Delete task definition");
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    let (habit_id, task_def_id) = path.into_inner();

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;
    let tx = conn.transaction().unwrap();

    let habit_id: Option<String> = tx
        .query_row_and_then(
            "SELECT id FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Task not found")));
    }

    let task_def_id: Option<String> = tx
        .query_row_and_then(
            "SELECT id FROM task_def WHERE id=?1 AND habit_id=?2",
            (&task_def_id, &habit_id),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if task_def_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Task not found")));
    }

    let result = tx.execute("DELETE FROM recurrence WHERE id=(SELECT recurrence_id FROM task_def WHERE id=?1 AND habit_id=?2)", (&task_def_id, &habit_id));
    match result {
        Ok(_) => {
            info!("deleted task recurrence");
        }
        Err(e) => {
            info!("error deleting task recurrence: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the task recurrence"
            )));
        }
    }

    let result = tx.execute("DELETE FROM task WHERE task_def_id=?1", [&task_def_id]);
    match result {
        Ok(_) => {
            info!("deleted tasks");
        }
        Err(e) => {
            info!("error deleting tasks: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting tasks"
            )));
        }
    }

    let result = tx.execute("DELETE FROM task_def WHERE id=?1", [&task_def_id]);
    match result {
        Ok(_) => {
            info!("deleted task definition");
        }
        Err(e) => {
            info!("error deleting task definitions: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when deleting the task definitions"
            )));
        }
    }
    let result = tx.commit();

    match result {
        Ok(_) => {
            info!("successfully commited the transaction");
        }
        Err(e) => {
            error!("error commiting the transaction: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when commiting delete task transaction"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[get("/habit/{habit_id}/tasks")]
async fn get_tasks(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    let habit_id = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    info!("Get tasks for habit = {} and user = {}", habit_id, username);

    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let habit_id: Option<String> = conn
        .query_row_and_then(
            "SELECT id FROM habit WHERE id=?1 AND username=?2",
            (&habit_id, &username),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let tasks: Vec<Task> = conn
        .prepare("SELECT t.id, td.name, t.state, t.due_on, t.done_on FROM task t JOIN task_def td ON t.task_def_id = td.id WHERE td.habit_id=?1")
        .unwrap()
        .query_map([&habit_id], |row| {
            Ok(Task{
                id: row.get(0).unwrap(),
                name: row.get(1).unwrap(),
                state: row.get(2).unwrap(),
                due_on: row.get(3).unwrap(),
                done_on: row.get(4).unwrap(),
            })
        })
        .unwrap()
        .map(|row| row.unwrap())
    .collect();

    Ok(HttpResponse::Ok().json(tasks))
}

#[put("/habit/{habit_id}/tasks/{task_id}")]
async fn complete_task(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    task: web::Json<TaskInput>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    let (habit_id, task_id) = path.into_inner();
    let username = authenticate(req.headers()).map_err(CustomError::AuthError)?;
    info!("Update task");

    let conn = state.conn.lock().expect("failed to lock conn");

    let habit_id: Option<String> = conn
        .query_row_and_then(
            "SELECT h.id FROM habit h JOIN task_def td ON h.id = td.habit_id JOIN task t ON td.id = t.task_def_id WHERE h.id=?1 AND h.username=?2 AND t.id=?3",
            (&habit_id, &username, &task_id),
            |row| row.get(0),
        )
        .optional()
        .unwrap();

    if habit_id.is_none() {
        return Err(CustomError::NotFound(anyhow::anyhow!("Habit not found")));
    }

    let db_task = conn
        .prepare("SELECT id, state, due_on, done_on FROM task where id=?1")
        .unwrap()
        .query_row([&task_id], |row| {
            Ok(Task {
                id: row.get(0).unwrap(),
                name: None,
                state: row.get(1).unwrap(),
                due_on: row.get(2).unwrap(),
                done_on: row.get(3).unwrap(),
            })
        })
        .unwrap();

    if db_task.state.as_ref().unwrap() != "Pending" {
        return Err(CustomError::BadRequest(anyhow::anyhow!(
            "Only tasks in Pending state can be changed"
        )));
    }

    if task.state != "Done" && task.state != "Cancelled" {
        return Err(CustomError::BadRequest(anyhow::anyhow!(
            "A task can only be transitioned to `Done` of `Cancelled` states"
        )));
    }

    let result = conn.execute(
        "UPDATE task SET state=?1, done_on=?2 WHERE id=?3",
        (&task.state, db_task.due_on, &task_id),
    );

    match result {
        Ok(updated) => {
            if updated == 0 {
                info!("error editing task");
                return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                    "Error when editing the task"
                )));
            }
            info!("edited task");
        }
        Err(e) => {
            info!("error editing task: {}", e);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when editing the task"
            )));
        }
    }

    Ok(HttpResponse::Ok().finish())
}

#[post("/user")]
async fn create_user(
    user: web::Json<CreateUser>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Create new user");
    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let password_hash = hash(&user.password);
    let result = conn.execute(
        "INSERT INTO user (username, password_hash, time_zone) VALUES (?1, ?2, ?3)",
        (&user.username, &password_hash, &user.time_zone),
    );
    match result {
        Ok(_) => {
            info!("inserted user");
        }
        Err(u) => {
            info!("error inserting user: {}", u);
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Error when saving the user"
            )));
        }
    }

    Ok(HttpResponse::Created().json(Jwt {
        token: generate_jwt(user.username.clone())?,
    }))
}

#[post("/login")]
async fn login(
    user: web::Json<LoginUser>,
    state: web::Data<State>,
) -> Result<HttpResponse, CustomError> {
    info!("Login user");
    let mut stmt_result = state.conn.lock().expect("failed to lock conn");
    let conn = &mut *stmt_result;

    let credentials = Credentials {
        username: user.username.clone(),
        password: user.password.parse().unwrap(),
    };
    validate_credentials(credentials, conn).await?;

    Ok(HttpResponse::Ok().json(Jwt {
        token: generate_jwt(user.username.clone())?,
    }))
}

fn generate_jwt(username: String) -> Result<String, CustomError> {
    const ONE_MONTH: Duration = Duration::new(60 * 60 * 24 * 31, 0);
    let token_exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + ONE_MONTH;
    let my_claims = Claims {
        sub: username.clone(),
        exp: usize::try_from(token_exp.as_secs()).unwrap(),
    };
    let token = match encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(get_jwt_key().as_bytes()),
    ) {
        Ok(t) => t,
        Err(err) => {
            return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                "Could not generate JWT {}",
                err
            )))
        }
    };

    Ok(token)
}

fn load_rustls_config() -> ServerConfig {
    let cert_file = &mut BufReader::new(
        File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/fullchain.pem").unwrap(),
    );
    let key_file = &mut BufReader::new(
        File::open("/etc/letsencrypt/live/backend.calendar.aguzovatii.com/privkey.pem").unwrap(),
    );

    let certs = rustls_pemfile::certs(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key = rustls_pemfile::private_key(key_file).unwrap().unwrap();

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap()
}

fn authenticate(headers: &HeaderMap) -> Result<String, anyhow::Error> {
    let header_value = headers
        .get("Authorization")
        .context("The 'Authorization' header was missing")?
        .to_str()
        .context("The 'Authorization' header was not a valid UTF8 string.")?;
    let jwt = header_value
        .strip_prefix("Bearer ")
        .context("The authorization scheme was not 'Bearer'.")?;

    let token_data = match decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(get_jwt_key().as_bytes()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(c) => c,
        Err(err) => {
            error!("err {:?}", err);
            return Err(anyhow::anyhow!("Invalid token: {}", err));
        }
    };

    Ok(token_data.claims.sub)
}

async fn validate_credentials(
    credentials: Credentials,
    conn: &Connection,
) -> Result<(), CustomError> {
    let mut stmt = conn
        .prepare("SELECT password_hash FROM user WHERE username = ?1")
        .unwrap();

    let password_hash: Option<String> = stmt
        .query_row([credentials.username.as_str()], |row| row.get(0))
        .optional()
        .unwrap();

    if password_hash.is_none() {
        return Err(CustomError::AuthError(anyhow::anyhow!(
            "Invalid username or password."
        )));
    }
    let password_hash = password_hash.unwrap();

    let expected_password = PasswordHash::new(&password_hash)
        .context("Failed to parse hash in PHC string format.")
        .map_err(CustomError::UnexpectedError)?;

    Argon2::default()
        .verify_password(
            credentials.password.expose_secret().as_bytes(),
            &expected_password,
        )
        .context("Invalid password.")
        .map_err(CustomError::AuthError)?;

    Ok(())
}

fn hash(password: &String) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());

    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn get_jwt_key() -> String {
    env::var("CALENDAR_JWT_SIGNING_KEY").unwrap_or(String::from("secret"))
}
