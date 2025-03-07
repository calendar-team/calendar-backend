use std::collections::HashSet;

use chrono::{DateTime, Datelike, Days, Months, NaiveDate, NaiveTime, Utc};
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
                let from = self
                    .recurrence
                    .from
                    .parse::<DateTime<Utc>>()
                    .unwrap()
                    .with_timezone(&date.timezone());

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
    pub(crate) fn naive_has_task_on(&self, date: NaiveDate, tz: &Tz) -> bool {
        let date = date
            .and_time(NaiveTime::default())
            .and_local_timezone(*tz)
            .unwrap()
            .to_utc();

        let mut count = 0;
        let mut due: DateTime<Utc> = self.get_first(tz).to_utc();
        loop {
            count += 1;
            if let crate::task::Ends::After { after } = self.ends_on {
                if count > after {
                    return false;
                }
            };

            if due >= date {
                return due == date;
            }

            due = self.get_next(due.with_timezone(tz)).to_utc();
        }
    }

    /// Returns a boolean indicating whether there should be a task on given date
    pub(crate) fn has_task_on(&self, date: NaiveDate, tz: &Tz) -> bool {
        let first_due: NaiveDate = self.get_first(tz).date_naive();

        if first_due > date {
            return false;
        }

        if first_due == date {
            return true;
        }

        match self.recurrence.rec_type {
            RecurrenceType::Days => {
                let num_days = (date - first_due).num_days() as u32;
                let every = self.recurrence.every;
                num_days % every == 0
                    && match self.ends_on {
                        Ends::Never => true,
                        Ends::After { after } => num_days / every < after,
                    }
            }

            RecurrenceType::Weeks => {
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

                let first_due_weekday = first_due.weekday() as u64;
                let monday_of_first_due = first_due
                    .checked_sub_days(Days::new(first_due_weekday))
                    .unwrap();
                let date_weekday = date.weekday() as u64;
                let monday_of_date = date.checked_sub_days(Days::new(date_weekday)).unwrap();

                let delta_weeks = (monday_of_date - monday_of_first_due).num_weeks() as u32;

                delta_weeks % self.recurrence.every == 0
                    && on_days.contains(&date_weekday)
                    && match self.ends_on {
                        Ends::Never => true,
                        Ends::After { after } => {
                            let mut counter = if delta_weeks > 1 {
                                (delta_weeks - 1) / self.recurrence.every * on_days.len() as u32
                            } else {
                                0
                            };

                            if delta_weeks == 0 {
                                for i in first_due_weekday..date_weekday + 1 {
                                    if on_days.contains(&i) {
                                        counter += 1;
                                    }
                                }
                                return counter <= after;
                            }
                            for i in first_due_weekday..7 {
                                if on_days.contains(&i) {
                                    counter += 1;
                                }
                            }

                            for i in 0..date_weekday + 1 {
                                if on_days.contains(&i) {
                                    counter += 1;
                                }
                            }
                            return counter <= after;
                        }
                    }
            }

            RecurrenceType::Months => self.naive_has_task_on(date, tz),

            RecurrenceType::Years => {
                if (date.year() - first_due.year()) % i32::try_from(self.recurrence.every).unwrap()
                    != 0
                {
                    return false;
                }

                if let Ends::After { after } = self.ends_on {
                    if (date.year() - first_due.year())
                        / i32::try_from(self.recurrence.every).unwrap()
                        > after.try_into().unwrap()
                    {
                        return false;
                    }
                }

                let new_date = first_due.with_year(date.year());

                if let Some(new_date) = new_date {
                    return new_date == date;
                }

                first_due
                    .with_day(1)
                    .unwrap()
                    .with_year(date.year())
                    .unwrap()
                    .checked_add_months(Months::new(1))
                    .unwrap()
                    .checked_sub_days(Days::new(1))
                    .unwrap()
                    == date
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
    pub is_future: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskInput {
    pub state: TaskState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskDetails {
    pub id: String,
    pub task_def_id: String,
    pub name: String,
    pub state: TaskState,
    pub due_on: String,
    pub done_on: Option<String>,
    pub is_future: bool,
    pub description: String,
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

    #[test]
    fn date_before_first_due_has_no_task() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2015-09-05", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_equal_to_first_due_has_a_task() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-25", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_a_task() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-29", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 3,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-29", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_task_when_3days_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 3,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::Never,
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-03", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_after_end() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 3,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::After { after: 1 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-03", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_task_when_equal_to_end() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 3,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-03", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_when_equal_to_end() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Days,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: None,
            },
            ends_on: Ends::After { after: 1 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-25", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);

        let date = NaiveDate::parse_from_str("2022-03-26", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_before_first_due_has_no_task_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-14", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_equal_to_start_date_has_no_task_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-25", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_equal_to_first_due_has_task_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-28", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-31", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_after_end_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 2 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-04", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_end_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 4 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-06", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_same_week_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Fri, WeekDay::Sun]
                        .into_iter()
                        .collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 2 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-27", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_next_week_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Fri, WeekDay::Sun]
                        .into_iter()
                        .collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 3 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-28", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_on_next_week_for_weeks_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Weeks,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Fri, WeekDay::Sun]
                        .into_iter()
                        .collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 3 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-01", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_before_first_due_has_no_task_for_months_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: vec![20].into_iter().collect(),
                }),
            },
            ends_on: Ends::After { after: 3 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-25", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_in_first_due_has_task_for_months_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: vec![25].into_iter().collect(),
                }),
            },
            ends_on: Ends::After { after: 3 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-25", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_last_day_of_month_for_months_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: vec![31].into_iter().collect(),
                }),
            },
            ends_on: Ends::After { after: 3 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-04-30", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_last_day_of_february_month_for_months_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: vec![30, 31].into_iter().collect(),
                }),
            },
            ends_on: Ends::After { after: 20 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2023-02-28", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_after_end_for_months_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Months,
                every: 1,
                from: "2022-03-24T22:00:00+00:00".to_string(),
                on_week_days: None,
                on_month_days: Some(MonthDays {
                    days: vec![30, 31].into_iter().collect(),
                }),
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "Europe/Bucharest".parse().unwrap();

        let date = NaiveDate::parse_from_str("2023-02-28", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_before_first_due_has_no_task_for_years_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 2 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-20", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_equal_to_first_due_has_task_for_years_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 2 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-03-24", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_for_years_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 2 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2022-07-24", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_task_for_years_recurrence() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2026-03-24", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_no_task_for_years_recurrence_after_end_date() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2033-03-24", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(!has_task);
    }

    #[test]
    fn date_after_first_due_has_task_for_years_recurrence_on_end_date() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2022-03-25T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2032-03-24", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_for_years_recurrence_on_leap_years() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2020-03-01T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2024-02-29", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }

    #[test]
    fn date_after_first_due_has_task_on_last_day_of_month_for_years_recurrence_on_non_leap_years() {
        let task_def = TaskDef {
            id: "abc".to_string(),
            name: "def".to_string(),
            description: "".to_string(),
            recurrence: Recurrence {
                rec_type: RecurrenceType::Years,
                every: 1,
                from: "2020-03-01T02:00:00+00:00".to_string(),
                on_week_days: Some(WeekDays {
                    days: vec![WeekDay::Mon, WeekDay::Wed].into_iter().collect(),
                }),
                on_month_days: None,
            },
            ends_on: Ends::After { after: 10 },
            state: TaskDefState::Active,
        };

        let tz: Tz = "America/Buenos_Aires".parse().unwrap();

        let date = NaiveDate::parse_from_str("2025-02-28", "%Y-%m-%d").unwrap();
        let has_task = task_def.has_task_on(date, &tz);
        assert!(has_task);
    }
}
