use calendar_backend_lib::{run, scheduler::start_task_scheduler, types::State};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use rusqlite::Connection;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::timeout;

#[derive(Deserialize)]
struct Jwt {
    token: String,
}

#[derive(Deserialize)]
struct Habit {
    id: String,
    name: String,
    state: String,
}

#[derive(Deserialize)]
struct HabitDetails {
    id: String,
    name: String,
    description: String,
}

#[derive(Deserialize)]
struct MonthDays {
    days: HashSet<u32>,
}

#[derive(Deserialize)]
struct WeekDays {
    days: HashSet<String>,
}

#[derive(Deserialize)]
struct Recurrence {
    rec_type: String,
    every: u32,
    from: String,
    on_week_days: Option<WeekDays>,
    on_month_days: Option<MonthDays>,
}

#[derive(Deserialize)]
struct TaskDef {
    id: String,
    name: String,
    description: String,
    recurrence: Recurrence,
}

#[derive(Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub state: String,
    pub due_on: String,
    pub done_on: Option<String>,
}

#[tokio::test]
async fn create_user_works() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());
}

#[tokio::test]
async fn cannot_create_user_if_username_already_taken() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    let user = serde_json::json!({
        "username": username,
        "password": "password",
        "time_zone": "Pacific/Palau",
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(StatusCode::BAD_REQUEST, response.status());
}

#[tokio::test]
async fn login_works_for_valid_credentials() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - login
    let user = serde_json::json!({
        "username": "djacota",
        "password": "password"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/login", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response_event.status().is_success());

    let jwt: Jwt = response_event.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());
}

#[tokio::test]
async fn login_fails_for_invalid_credentials() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - login
    let user = serde_json::json!({
        "username": "djacota",
        "password": "wrong_password"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/login", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(StatusCode::UNAUTHORIZED, response_event.status());
}

#[tokio::test]
async fn create_habit_works() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());
}

#[tokio::test]
async fn delete_habit_works() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create another habit
    let habit = serde_json::json!({"name": "daily coffee", "description": "COFFEE!!"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let response_habit = reqwest::Client::new()
        .delete(&format!("{}/habit/{}", &address, habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed to delete habit.");

    // Assert
    assert!(response_habit.status().is_success());
    assert_eq!(Some(0), response_habit.content_length());

    // Act - get all the habits
    let response_habits = reqwest::Client::new()
        .get(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habits.status().is_success());
    let habits: Vec<Habit> = response_habits.json::<Vec<Habit>>().await.unwrap();
    assert_eq!(1, habits.len());
    assert_eq!("daily coffee", habits[0].name);
}

#[tokio::test]
async fn edit_habit_works() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - prepare habit to be edited
    let habit = serde_json::json!({
        "name": "daily yoga",
        "description": "Check Yoga With Adriene",
    });

    // Act - edit habit
    let response_habit = reqwest::Client::new()
        .put(&format!("{}/habit/{}", &address, habit_id))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert!(response_habit.status().is_success());
    assert_eq!(Some(0), response_habit.content_length());

    // Act - get all the habits
    let response_habits = reqwest::Client::new()
        .get(&format!("{}/habit", &address))
        .bearer_auth(jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habits.status().is_success());
    let habits: Vec<Habit> = response_habits.json::<Vec<Habit>>().await.unwrap();
    assert_eq!(1, habits.len());
    assert_eq!("daily yoga", habits[0].name);
    assert_eq!("Done", habits[0].state);
    assert_eq!(habit_id, habits[0].id);
}

#[tokio::test]
async fn edit_habit_requests_missing_authorization_are_rejected() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": "after workout"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Act - edit habit
    let response_habit = reqwest::Client::new()
        .put(&format!("{}/habit/{}", &address, habit_id))
        .json(&habit)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(401, response_habit.status().as_u16());
}

#[tokio::test]
async fn edit_non_existent_habit_rejected() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    let habit = serde_json::json!({"name": "daily yoga", "description": ""});

    // Act - edit habit
    let response_habit = reqwest::Client::new()
        .put(&format!("{}/habit/test", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(404, response_habit.status().as_u16());
}

#[tokio::test]
async fn get_habit_details_correctly_returned() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": "daily at 08:00"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Act - get habit details
    let response_habit = reqwest::Client::new()
        .get(&format!("{}/habit/{}", &address, habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habit.status().is_success());
    let habit_details: HabitDetails = response_habit.json::<HabitDetails>().await.unwrap();
    assert_eq!("daily stretch", habit_details.name);
    assert_eq!("daily at 08:00", habit_details.description);
    assert_eq!(habit_id, habit_details.id);
}

#[tokio::test]
async fn get_habit_details_requests_missing_authorization_are_rejected() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily stretch", "description": "after workout"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Act - get habit details
    let response_habit = reqwest::Client::new()
        .get(&format!("{}/habit/{}", &address, habit_id))
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(401, response_habit.status().as_u16());
}

#[tokio::test]
async fn get_habit_details_for_non_existent_habit_is_rejected() {
    // Arrange - create the user
    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Act - get habit details
    let response_habit = reqwest::Client::new()
        .get(&format!("{}/habit/test", &address))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(404, response_habit.status().as_u16());
}

#[tokio::test]
async fn create_task_def_works() {
    // Arrange - create the user
    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-15T13:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let (address, _) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "sport", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create the habit
    let other_habit = serde_json::json!({"name": "reading", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&other_habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());
    let other_habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create task def
    let task_def = serde_json::json!({"name": "running", "description": "Run 10km", "recurrence": {"rec_type": "Days", "every": 1, "from": "2022-03-12T22:00:01+00:00" }, "ends_on": {"type": "Never"}});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create another task def
    let task_def = serde_json::json!({"name": "swimming", "description": "Swim 10km", "recurrence": {"rec_type": "Weeks", "every": 2, "from": "2022-03-05T22:00:02+00:00", "on_week_days" : { "days" : ["Tue", "Sat"]}}, "ends_on": {"type": "Never"}});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create a task def for other habit
    let task_def = serde_json::json!({"name": "Read before sleep", "description": "Read 10 min", "recurrence": {"rec_type": "Months", "every": 3, "from": "2022-03-12T22:00:03+00:00", "on_month_days": { "days": [13, 21]}}, "ends_on": {"type": "Never"}});

    // Act
    let response = reqwest::Client::new()
        .post(&format!(
            "{}/habit/{}/tasks_defs",
            &address, &other_habit_id
        ))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - get all tasks defs for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks_defs = response_tasks_defs.json::<Vec<TaskDef>>().await.unwrap();
    tasks_defs.sort_by(|td1, td2| td1.name.cmp(&td2.name));

    assert_eq!(2, tasks_defs.len());
    assert!(!tasks_defs[0].id.is_empty());
    assert_eq!("running", tasks_defs[0].name);
    assert_eq!("Run 10km", tasks_defs[0].description);
    assert_eq!("Days", tasks_defs[0].recurrence.rec_type);
    assert_eq!(1, tasks_defs[0].recurrence.every);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks_defs[0].recurrence.from);
    assert!(tasks_defs[0].recurrence.on_week_days.is_none());
    assert!(tasks_defs[0].recurrence.on_month_days.is_none());

    assert!(!tasks_defs[1].id.is_empty());
    assert_eq!("swimming", tasks_defs[1].name);
    assert_eq!("Swim 10km", tasks_defs[1].description);
    assert_eq!("Weeks", tasks_defs[1].recurrence.rec_type);
    assert_eq!(2, tasks_defs[1].recurrence.every);
    assert_eq!("2022-03-05T22:00:02+00:00", tasks_defs[1].recurrence.from);
    assert_eq!(
        HashSet::from(["Tue".to_string(), "Sat".to_string()]),
        tasks_defs[1].recurrence.on_week_days.as_ref().unwrap().days
    );
    assert!(tasks_defs[1].recurrence.on_month_days.is_none());

    // Act - get all tasks defs for other habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!(
            "{}/habit/{}/tasks_defs",
            &address, &other_habit_id
        ))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let tasks_defs = response_tasks_defs.json::<Vec<TaskDef>>().await.unwrap();

    assert_eq!(1, tasks_defs.len());
    assert!(!tasks_defs[0].id.is_empty());
    assert_eq!("Read before sleep", tasks_defs[0].name);
    assert_eq!("Read 10 min", tasks_defs[0].description);
    assert_eq!("Months", tasks_defs[0].recurrence.rec_type);
    assert_eq!(3, tasks_defs[0].recurrence.every);
    assert_eq!("2022-03-12T22:00:03+00:00", tasks_defs[0].recurrence.from);
    assert!(tasks_defs[0].recurrence.on_week_days.is_none());
    assert_eq!(
        HashSet::from([13, 21]),
        tasks_defs[0]
            .recurrence
            .on_month_days
            .as_ref()
            .unwrap()
            .days
    );

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(4, tasks.len());
    assert!(!tasks[0].id.is_empty());
    assert_eq!("running", tasks[0].name);
    assert_eq!("Pending", tasks[0].state);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);
    assert!(tasks[0].done_on.is_none());

    assert!(!tasks[1].id.is_empty());
    assert_eq!("running", tasks[1].name);
    assert_eq!("Pending", tasks[1].state);
    assert_eq!("2022-03-13T22:00:01+00:00", tasks[1].due_on);
    assert!(tasks[1].done_on.is_none());

    assert!(!tasks[2].id.is_empty());
    assert_eq!("running", tasks[2].name);
    assert_eq!("Pending", tasks[2].state);
    assert_eq!("2022-03-14T22:00:01+00:00", tasks[2].due_on);
    assert!(tasks[2].done_on.is_none());

    assert!(!tasks[3].id.is_empty());
    assert_eq!("swimming", tasks[3].name);
    assert_eq!("Pending", tasks[3].state);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[3].due_on);
    assert!(tasks[3].done_on.is_none());

    // Act - get all tasks for other habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &other_habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();

    assert_eq!(1, tasks.len());
    assert!(!tasks[0].id.is_empty());
    assert_eq!("Read before sleep", tasks[0].name);
    assert_eq!("Pending", tasks[0].state);
    assert_eq!("2022-03-12T22:00:03+00:00", tasks[0].due_on);
    assert!(tasks[0].done_on.is_none());

    let state = serde_json::json!({"state": "Done"});

    // Act - mark task as done
    let response = reqwest::Client::new()
        .put(&format!(
            "{}/habit/{}/tasks/{}",
            &address, &other_habit_id, tasks[0].id
        ))
        .bearer_auth(&jwt.token)
        .json(&state)
        .send()
        .await
        .expect("Failed the get all the habits.");

    assert!(response.status().is_success());

    // Act - get all tasks for other habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &other_habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();

    assert_eq!(1, tasks.len());
    assert!(!tasks[0].id.is_empty());
    assert_eq!("Read before sleep", tasks[0].name);
    assert_eq!("Done", tasks[0].state);
    assert_eq!("2022-03-12T22:00:03+00:00", tasks[0].due_on);
    assert_eq!(
        "2022-03-12T22:00:03+00:00",
        &tasks[0].done_on.clone().unwrap()
    );
}

#[tokio::test]
async fn scheduler_works() {
    // Arrange - create the user
    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-15T13:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let (address, state) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "sport", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create the habit
    let other_habit = serde_json::json!({"name": "reading", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&other_habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());
    let other_habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create task def
    let task_def = serde_json::json!({"name": "running", "description": "Run 10km", "recurrence": {"rec_type": "Days", "every": 7, "from": "2022-03-12T22:00:01+00:00"}, "ends_on": { "type": "Never" }});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create another task def
    let task_def = serde_json::json!({"name": "swimming", "description": "Swim 10km", "recurrence": {"rec_type": "Weeks", "every": 2, "from": "2022-03-05T22:00:02+00:00", "on_week_days" : { "days" : ["Tue", "Sat"]}}, "ends_on": { "type": "Never" }});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create a task def for other habit
    let task_def = serde_json::json!({"name": "Read before sleep", "description": "Read 10 min", "recurrence": {"rec_type": "Months", "every": 3, "from": "2022-03-12T22:00:03+00:00", "on_month_days": { "days": [13, 21]}}, "ends_on": { "type": "Never" }});

    // Act
    let response = reqwest::Client::new()
        .post(&format!(
            "{}/habit/{}/tasks_defs",
            &address, &other_habit_id
        ))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(2, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("swimming", tasks[1].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[1].due_on);

    tokio::time::pause();

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-18T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(2, tasks.len());

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-18T22:00:02+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(3, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("swimming", tasks[1].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[1].due_on);

    assert_eq!("swimming", tasks[2].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[2].due_on);

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-20T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(4, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("swimming", tasks[2].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[2].due_on);

    assert_eq!("swimming", tasks[3].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[3].due_on);

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-04-10T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(6, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("running", tasks[2].name);
    assert_eq!("2022-03-26T22:00:01+00:00", tasks[2].due_on);

    assert_eq!("swimming", tasks[3].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[3].due_on);

    assert_eq!("swimming", tasks[4].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[4].due_on);

    assert_eq!("swimming", tasks[5].name);
    assert_eq!("2022-03-28T21:00:02+00:00", tasks[5].due_on);

    let _ = timeout(Duration::from_secs(3602), start_task_scheduler(state)).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(9, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("running", tasks[2].name);
    assert_eq!("2022-03-26T22:00:01+00:00", tasks[2].due_on);

    assert_eq!("running", tasks[3].name);
    assert_eq!("2022-04-02T21:00:01+00:00", tasks[3].due_on);

    assert_eq!("running", tasks[4].name);
    assert_eq!("2022-04-09T21:00:01+00:00", tasks[4].due_on);

    assert_eq!("swimming", tasks[5].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[5].due_on);

    assert_eq!("swimming", tasks[6].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[6].due_on);

    assert_eq!("swimming", tasks[7].name);
    assert_eq!("2022-03-28T21:00:02+00:00", tasks[7].due_on);

    assert_eq!("swimming", tasks[8].name);
    assert_eq!("2022-04-01T21:00:02+00:00", tasks[8].due_on);
}

#[tokio::test]
async fn scheduler_respects_end_condition() {
    // Arrange - create the user
    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-15T13:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let (address, state) = spawn_app();
    let username = "djacota";
    let password = "password";
    let time_zone = "Europe/Bucharest";

    let user = serde_json::json!({
        "username": username,
        "password": password,
        "time_zone": time_zone,
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/user", &address))
        .json(&user)
        .send()
        .await
        .expect("Failed to create a new user.");

    // Assert
    assert!(response.status().is_success());

    let jwt: Jwt = response.json::<Jwt>().await.unwrap();
    assert!(!jwt.token.is_empty());

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "sport", "description": ""});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(&jwt.token)
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    let habit_id = response.json::<HabitDetails>().await.unwrap().id;

    // Arrange - create task def
    let task_def = serde_json::json!({"name": "running", "description": "Run 10km", "recurrence": {"rec_type": "Days", "every": 7, "from": "2022-03-12T22:00:01+00:00"}, "ends_on": { "type": "Never" }});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create another task def
    let task_def = serde_json::json!({"name": "swimming", "description": "Swim 10km", "recurrence": {"rec_type": "Weeks", "every": 2, "from": "2022-03-05T22:00:02+00:00", "on_week_days" : { "days" : ["Tue", "Sat"]}}, "ends_on": { "type": "After", "value": { "after": 2 } }});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .json(&task_def)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(2, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("swimming", tasks[1].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[1].due_on);

    tokio::time::pause();

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-18T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(2, tasks.len());

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-18T22:00:02+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(3, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("swimming", tasks[1].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[1].due_on);

    assert_eq!("swimming", tasks[2].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[2].due_on);

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-03-20T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(4, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("swimming", tasks[2].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[2].due_on);

    assert_eq!("swimming", tasks[3].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[3].due_on);

    {
        let mut date = MOCK_UTC_NOW.lock().unwrap();
        *date = Some(
            DateTime::parse_from_rfc3339("2022-04-10T12:00:00+00:00")
                .unwrap()
                .to_utc(),
        );
    }

    let _ = timeout(Duration::from_secs(2), start_task_scheduler(state.clone())).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(5, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("running", tasks[2].name);
    assert_eq!("2022-03-26T22:00:01+00:00", tasks[2].due_on);

    assert_eq!("swimming", tasks[3].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[3].due_on);

    assert_eq!("swimming", tasks[4].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[4].due_on);

    let _ = timeout(Duration::from_secs(3602), start_task_scheduler(state)).await;

    // Act - get all tasks for habit
    let response_tasks_defs = reqwest::Client::new()
        .get(&format!("{}/habit/{}/tasks", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks = response_tasks_defs.json::<Vec<Task>>().await.unwrap();
    tasks.sort_by(|td1, td2| td1.name.cmp(&td2.name).then(td1.due_on.cmp(&td2.due_on)));

    assert_eq!(7, tasks.len());
    assert_eq!("running", tasks[0].name);
    assert_eq!("2022-03-12T22:00:01+00:00", tasks[0].due_on);

    assert_eq!("running", tasks[1].name);
    assert_eq!("2022-03-19T22:00:01+00:00", tasks[1].due_on);

    assert_eq!("running", tasks[2].name);
    assert_eq!("2022-03-26T22:00:01+00:00", tasks[2].due_on);

    assert_eq!("running", tasks[3].name);
    assert_eq!("2022-04-02T21:00:01+00:00", tasks[3].due_on);

    assert_eq!("running", tasks[4].name);
    assert_eq!("2022-04-09T21:00:01+00:00", tasks[4].due_on);

    assert_eq!("swimming", tasks[5].name);
    assert_eq!("2022-03-14T22:00:02+00:00", tasks[5].due_on);

    assert_eq!("swimming", tasks[6].name);
    assert_eq!("2022-03-18T22:00:02+00:00", tasks[6].due_on);
}

static MOCK_UTC_NOW: Mutex<Option<DateTime<Utc>>> = Mutex::new(None);
fn mock_utc_now() -> DateTime<Utc> {
    MOCK_UTC_NOW.lock().unwrap().unwrap_or_else(Utc::now)
}

// launch the server as a background task
fn spawn_app() -> (String, State) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");

    // We retrieve the port assigned to us by the OS
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::open_in_memory().unwrap();
    let state = calendar_backend_lib::types::State {
        conn: Arc::new(Mutex::new(conn)),
        utc_now: mock_utc_now,
    };

    let server = run(listener, state.clone()).expect("Failed to bind address");
    tokio::spawn(server);

    // We return the application address to the caller
    (format!("http://127.0.0.1:{}", port), state)
}
