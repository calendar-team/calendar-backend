use std::collections::HashSet;

use chrono::{DateTime, Datelike, Days, Months, Utc};
use chrono_tz::Tz;
use log::info;
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

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone)]
#[serde(tag = "type", content = "value")]
pub enum Ends {
    Never,
    After { after: u32 },
}

impl rusqlite::ToSql for Ends {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl rusqlite::types::FromSql for Ends {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rec: Ends = serde_json::from_str(value.as_str()?).unwrap();
        Ok(rec)
    }
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
    pub ends_on: Ends,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskDefState {
    Active,
    Finished,
}

impl rusqlite::ToSql for TaskDefState {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(serde_json::to_string(self).unwrap()))
    }
}

impl rusqlite::types::FromSql for TaskDefState {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let rec: TaskDefState = serde_json::from_str(value.as_str()?).unwrap();
        Ok(rec)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskDef {
    pub id: String,
    pub name: String,
    pub description: String,
    pub recurrence: Recurrence,
    pub ends_on: Ends,
    pub state: TaskDefState,
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

    /// Returns the boolean indicating whether there should be a task on given date
    pub(crate) fn get_task_for(&self, tz: &Tz, date: DateTime<Utc>) -> bool {
        let mut count = 0;
        let mut last_due: Option<DateTime<Utc>> = None;
        info!("ajuns");
        loop {
            let next_due = match last_due {
                Some(last_due) => self.get_next(last_due.with_timezone(&tz)),
                None => self.get_first(&tz),
            }
            .to_utc();

            info!(
                "Task ({}), next_due={}, last_due={:?}, count={}",
                self.name, next_due, last_due, count
            );

            if next_due < date {
                count += 1;
                if let crate::task::Ends::After { after } = self.ends_on {
                    if count == after {
                        return false;
                    }
                };
                last_due = Some(next_due);
            } else {
                info!("compare: {} == {} = {}", next_due, date, next_due == date);
                return next_due == date;
            }
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
    pub task_def_id: String,
    pub name: String,
    pub state: TaskState,
    pub due_on: String,
    pub done_on: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskInput {
    pub state: TaskState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daily_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Daily task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 1,
                from: "2024-03-13T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-13T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-14T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-15T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }

    #[test]
    fn test_once_in_3_days_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Once in 3 days task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 3,
                from: "2024-03-26T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-26T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-29T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-04-01T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }

    #[test]
    fn test_weekly_on_monday_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Weekly on Monday task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2024-03-13T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: HashSet::from([WeekDay::Mon]),
                }),
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-17T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-24T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-31T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }

    #[test]
    fn test_once_in_3_weeks_on_mon_and_tue_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Once in 3 weeks on Monday task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 3,
                from: "2024-03-13T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: HashSet::from([WeekDay::Mon, WeekDay::Tue]),
                }),
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-31T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-04-01T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-04-21T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }

    #[test]
    fn test_monthly_on_31_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Monthly on 31 task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2024-02-13T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: HashSet::from([31]),
                }),
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-02-28T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-30T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-04-29T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }

    #[test]
    fn test_once_in_3_months_on_30_and_31_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Once in 3 months on 30 and 31 task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 3,
                from: "2024-03-30T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: HashSet::from([30, 31]),
                }),
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-03-30T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-06-29T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-09-29T21:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );

        let fourth_due = task_def.get_next(third_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-12-29T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            fourth_due
        );

        let fifth_due = task_def.get_next(fourth_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-12-30T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            fifth_due
        );
    }

    #[test]
    fn test_yearly_on_29_feb_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Yearly on 29th of Feb task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2020-02-28T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2020-02-28T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2021-02-27T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2022-02-27T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );

        let fourth_due = task_def.get_next(third_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2023-02-27T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            fourth_due
        );

        let fifth_due = task_def.get_next(fourth_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2024-02-28T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            fifth_due
        );
    }

    #[test]
    fn test_every_5_years_on_25_mar_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "Every 5 years on 25th of March task".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 5,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();
        let first_due = task_def.get_first(&tz);
        assert_eq!(
            DateTime::parse_from_rfc3339("2022-03-24T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            first_due
        );

        let second_due = task_def.get_next(first_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2027-03-24T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            second_due
        );

        let third_due = task_def.get_next(second_due);
        assert_eq!(
            DateTime::parse_from_rfc3339("2032-03-24T22:00:00+00:00")
                .unwrap()
                .with_timezone(&tz),
            third_due
        );
    }
}
