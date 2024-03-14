use std::collections::HashSet;

use chrono::{DateTime, Datelike, Days, Months, Utc};
use chrono_tz::Tz;
use rusqlite::types::{FromSqlResult, ToSqlOutput, ValueRef};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RecurrenceType {
    Days,
    Weeks,
    Months,
    Years,
}

impl rusqlite::ToSql for RecurrenceType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl rusqlite::types::FromSql for RecurrenceType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rec: RecurrenceType = serde_json::from_str(value.as_str()?).unwrap();
        Ok(rec)
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone)]
pub enum WeekDay {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeekDays {
    pub days: HashSet<WeekDay>,
}

impl rusqlite::ToSql for WeekDays {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl rusqlite::types::FromSql for WeekDays {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rec: WeekDays = serde_json::from_str(value.as_str()?).unwrap();
        Ok(rec)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonthDays {
    pub days: HashSet<u32>,
}

impl rusqlite::ToSql for MonthDays {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl rusqlite::types::FromSql for MonthDays {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rec: MonthDays = serde_json::from_str(value.as_str()?).unwrap();
        Ok(rec)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Recurrence {
    pub rec_type: RecurrenceType,
    pub every: u32,
    pub from: String,
    pub on_week_days: Option<WeekDays>,
    pub on_month_days: Option<MonthDays>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskDefInput {
    pub name: String,
    pub description: String,
    pub recurrence: Recurrence,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskDef {
    pub id: String,
    pub name: String,
    pub description: String,
    pub recurrence: Recurrence,
}

impl TaskDef {
    /// Returns the due date of the task that should follow after a task on given date
    pub(crate) fn get_next(&self, date: DateTime<Tz>) -> DateTime<Tz> {
        let from = self
            .recurrence
            .from
            .parse::<DateTime<Utc>>()
            .unwrap()
            .with_timezone(&date.timezone());
        match self.recurrence.rec_type {
            RecurrenceType::Days => date + Days::new(self.recurrence.every.into()),

            RecurrenceType::Weeks => {
                let day = date.weekday() as u64;
                let on_days: HashSet<u64> = self
                    .recurrence
                    .on_week_days
                    .as_ref()
                    .unwrap()
                    .days
                    .clone()
                    .into_iter()
                    .map(|v| v as u64)
                    .collect();

                for i in (day + 1)..7 {
                    if on_days.contains(&i) {
                        return date + Days::new(i - day);
                    }
                }

                let min = on_days.iter().min().unwrap();

                date.checked_add_days(Days::new((7 * self.recurrence.every).into()))
                    .unwrap()
                    .checked_sub_days(Days::new(day - min))
                    .unwrap()
            }

            RecurrenceType::Months => {
                let day = date.day();
                let on_days = &self.recurrence.on_month_days.as_ref().unwrap().days;
                for i in (day + 1)..32 {
                    if on_days.contains(&i) {
                        let new_date = date.with_day(i);
                        if let Some(new_date) = new_date {
                            return new_date;
                        }
                        let new_date = date
                            .with_day(1)
                            .unwrap()
                            .checked_add_months(Months::new(1))
                            .unwrap()
                            .checked_sub_days(Days::new(1))
                            .unwrap();
                        if new_date.day() > day {
                            return new_date;
                        }
                    }
                }

                let min = *on_days.iter().min().unwrap();

                let new_date = date
                    .checked_add_months(Months::new(self.recurrence.every))
                    .unwrap();

                if let Some(new_date) = new_date.with_day(min) {
                    return new_date;
                }

                new_date
                    .with_day(1)
                    .unwrap()
                    .checked_add_months(Months::new(1))
                    .unwrap()
                    .checked_sub_days(Days::new(1))
                    .unwrap()
            }

            RecurrenceType::Years => {
                let new_date =
                    from.with_year(date.year() + i32::try_from(self.recurrence.every).unwrap());

                if let Some(new_date) = new_date {
                    return new_date;
                }

                from.with_day(1)
                    .unwrap()
                    .with_year(date.year() + i32::try_from(self.recurrence.every).unwrap())
                    .unwrap()
                    .checked_add_months(Months::new(1))
                    .unwrap()
                    .checked_sub_days(Days::new(1))
                    .unwrap()
            }
        }
    }

    /// Returns the due date of the first task for this recurrence in the given time zone
    pub(crate) fn get_first(&self, tz: &Tz) -> DateTime<Tz> {
        let from = self
            .recurrence
            .from
            .parse::<DateTime<Utc>>()
            .unwrap()
            .with_timezone(tz);

        match self.recurrence.rec_type {
            RecurrenceType::Days => from,

            RecurrenceType::Weeks => {
                let day = from.weekday() as u64;
                let on_days: HashSet<u64> = self
                    .recurrence
                    .on_week_days
                    .as_ref()
                    .unwrap()
                    .days
                    .clone()
                    .into_iter()
                    .map(|v| v as u64)
                    .collect();

                for i in day..7 {
                    if on_days.contains(&i) {
                        return from + Days::new(i - day);
                    }
                }

                let min = on_days.iter().min().unwrap();

                from.checked_add_days(Days::new((7 * self.recurrence.every).into()))
                    .unwrap()
                    .checked_sub_days(Days::new(day - min))
                    .unwrap()
            }

            RecurrenceType::Months => {
                let day = from.day();
                let on_days = &self.recurrence.on_month_days.as_ref().unwrap().days;
                for i in day..32 {
                    if on_days.contains(&i) {
                        let new_date = from.with_day(i);
                        if let Some(new_date) = new_date {
                            return new_date;
                        }
                        let new_date = from
                            .with_day(1)
                            .unwrap()
                            .checked_add_months(Months::new(1))
                            .unwrap()
                            .checked_sub_days(Days::new(1))
                            .unwrap();
                        if new_date.day() >= day {
                            return new_date;
                        }
                    }
                }

                let min = *on_days.iter().min().unwrap();

                let new_date = from
                    .checked_add_months(Months::new(self.recurrence.every))
                    .unwrap();

                if let Some(new_date) = new_date.with_day(min) {
                    return new_date;
                }

                new_date
                    .checked_add_months(Months::new(1))
                    .unwrap()
                    .checked_sub_days(Days::new(1))
                    .unwrap()
            }

            RecurrenceType::Years => from,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskState {
    Pending,
    Done,
    Cancelled,
}

impl rusqlite::types::FromSql for TaskState {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let state: TaskState = serde_json::from_str(value.as_str()?).unwrap();
        Ok(state)
    }
}

impl rusqlite::ToSql for TaskState {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub state: TaskState,
    pub due_on: String,
    pub done_on: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskInput {
    pub state: TaskState,
}
