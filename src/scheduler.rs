use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use log::{error, info};
use rusqlite::Transaction;
use tokio::time;
use uuid::Uuid;

use crate::{
    task::{Recurrence, TaskDef, TaskState},
    types::{State, UtcNowFn},
    CustomError,
};

#[derive(Debug)]
struct TaskRec {
    def: TaskDef,
    last_due: Option<String>,
    time_zone: String,
}

pub async fn start_task_scheduler(state: State) {
    let mut interval = time::interval(time::Duration::from_secs(60 * 60));
    loop {
        interval.tick().await;
        schedule(&state).await;
    }
}

pub fn schedule_tasks(
    task_def: &TaskDef,
    tz: Tz,
    tx: &Transaction,
    utc_now: UtcNowFn,
) -> std::result::Result<(), CustomError> {
    let now = utc_now();
    let mut last_due: Option<DateTime<Utc>> = None;
    loop {
        let next_due = match last_due {
            Some(last_due) => task_def.get_next(last_due.with_timezone(&tz)),
            None => task_def.get_first(&tz),
        }
        .to_utc();

        if next_due <= now {
            let task_id = Uuid::new_v4();
            match tx.execute(
                "INSERT INTO task (id, task_def_id, state, due_on) VALUES (?1, ?2, ?3, ?4)",
                (
                    &task_id.to_string(),
                    &task_def.id,
                    TaskState::Pending,
                    next_due.to_rfc3339(),
                ),
            ) {
                Ok(_) => {}
                Err(e) => {
                    error!("Error creating new task: {}", e);
                    return Err(CustomError::UnexpectedError(anyhow::anyhow!(
                        "Error when commiting create task definition transaction"
                    )));
                }
            };
            last_due = Some(next_due);
        } else {
            return Ok(());
        }
    }
}

async fn schedule(state: &State) {
    let tasks: Vec<TaskRec> = state.conn.lock().unwrap()
        .prepare("SELECT td.id, td.name, td.description, r.type, r.every, r.from_date, r.on_week_days, r.on_month_days, MAX(t.due_on), u.time_zone FROM task_def td JOIN recurrence r ON td.recurrence_id = r.id LEFT JOIN task t ON td.id = t.task_def_id JOIN habit h ON td.habit_id = h.id JOIN user u ON h.username = u.username GROUP BY td.id")
        .unwrap()
        .query_map([], |row| {
            Ok(TaskRec{
                def: TaskDef {
                    id: row.get(0).unwrap(),
                    name: row.get(1).unwrap(),
                    description: row.get(2).unwrap(),
                    recurrence: Recurrence {
                        rec_type: row.get(3).unwrap(),
                        every: row.get(4).unwrap(),
                        from: row.get(5).unwrap(),
                        on_week_days: row.get(6).unwrap(),
                        on_month_days: row.get(7).unwrap(),
                    },
                },
                last_due: row.get(8).unwrap(),
                time_zone: row.get(9).unwrap(),
            })
        })
        .unwrap()
        .map(|row| row.unwrap())
        .collect();

    let now = (state.utc_now)();

    for task in tasks {
        let tz: Tz = task.time_zone.parse().unwrap();
        let next_due = match task.last_due {
            Some(last_due) => task.def.get_next(
                last_due
                    .parse::<DateTime<Utc>>()
                    .unwrap()
                    .with_timezone(&tz),
            ),
            None => task.def.get_first(&tz),
        }
        .to_utc();

        if next_due <= now {
            info!(
                "Creating new task for {}({}) with due date on {}",
                task.def.name,
                task.def.id,
                next_due.to_rfc3339(),
            );
            let task_id = Uuid::new_v4();
            match state.conn.lock().unwrap().execute(
                "INSERT INTO task (id, task_def_id, state, due_on) VALUES (?1, ?2, ?3, ?4)",
                (
                    &task_id.to_string(),
                    task.def.id,
                    TaskState::Pending,
                    next_due.to_rfc3339(),
                ),
            ) {
                Ok(_) => {}
                Err(e) => {
                    error!("Error creating new task: {}", e);
                }
            };
        }
    }
}
