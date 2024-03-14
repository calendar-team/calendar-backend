use calendar_backend_lib::run;
use reqwest::StatusCode;
use rusqlite::Connection;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::TcpListener,
    sync::{Arc, Mutex},
};

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

#[tokio::test]
async fn create_user_works() {
    // Arrange - create the user
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let address = spawn_app();
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
    let task_def = serde_json::json!({"name": "running", "description": "Run 10km", "recurrence": {"rec_type": "Days", "every": 1000, "from": "2022-03-13T22:00:01+00:00"}});

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
    let task_def = serde_json::json!({"name": "swimming", "description": "Swim 10km", "recurrence": {"rec_type": "Weeks", "every": 200, "from": "2022-03-13T22:00:02+00:00", "on_week_days" : { "days" : ["Tue", "Fri"]}}});

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
    let task_def = serde_json::json!({"name": "Read before sleep", "description": "Read 10 min", "recurrence": {"rec_type": "Months", "every": 30, "from": "2022-03-13T22:00:03+00:00", "on_month_days": { "days": [13, 21]}}});

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
        .get(&format!("{}/habit/{}/tasks_defs", &address, &habit_id))
        .bearer_auth(&jwt.token)
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_tasks_defs.status().is_success());
    let mut tasks_defs = response_tasks_defs.json::<Vec<TaskDef>>().await.unwrap();
    tasks_defs.sort_by_key(|td| td.name.clone());

    assert_eq!(2, tasks_defs.len());
    assert!(!tasks_defs[0].id.is_empty());
    assert_eq!("running", tasks_defs[0].name);
    assert_eq!("Run 10km", tasks_defs[0].description);
    assert_eq!("Days", tasks_defs[0].recurrence.rec_type);
    assert_eq!(1000, tasks_defs[0].recurrence.every);
    assert_eq!("2022-03-13T22:00:01+00:00", tasks_defs[0].recurrence.from);
    assert!(tasks_defs[0].recurrence.on_week_days.is_none());
    assert!(tasks_defs[0].recurrence.on_month_days.is_none());

    assert!(!tasks_defs[1].id.is_empty());
    assert_eq!("swimming", tasks_defs[1].name);
    assert_eq!("Swim 10km", tasks_defs[1].description);
    assert_eq!("Weeks", tasks_defs[1].recurrence.rec_type);
    assert_eq!(200, tasks_defs[1].recurrence.every);
    assert_eq!("2022-03-13T22:00:02+00:00", tasks_defs[1].recurrence.from);
    assert_eq!(
        HashSet::from(["Tue".to_string(), "Fri".to_string()]),
        tasks_defs[1].recurrence.on_week_days.as_ref().unwrap().days
    );
    assert!(tasks_defs[1].recurrence.on_month_days.is_none());

    // Act - get all tasks for other habit
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
    assert_eq!(30, tasks_defs[0].recurrence.every);
    assert_eq!("2022-03-13T22:00:03+00:00", tasks_defs[0].recurrence.from);
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
}

// launch the server as a background task
fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");

    // We retrieve the port assigned to us by the OS
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::open_in_memory().unwrap();
    let state = calendar_backend_lib::types::State {
        conn: Arc::new(Mutex::new(conn)),
    };

    let server = run(listener, state).expect("Failed to bind address");
    tokio::spawn(server);

    // We return the application address to the caller
    format!("http://127.0.0.1:{}", port)
}
