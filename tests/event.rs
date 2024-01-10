use actix_web::http::StatusCode;
use calendar_backend::run;
use chrono::Utc;
use rusqlite::Connection;
use serde::Deserialize;
use std::net::TcpListener;

#[derive(Deserialize)]
struct Jwt {
    token: String,
}

#[derive(Deserialize)]
struct Event {
    habit: String,
    date_time: String,
}

#[derive(Deserialize)]
struct Calendar {
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Habit {
    name: String,
    state: String,
}

#[derive(Deserialize)]
struct HabitDetails {
    name: String,
    description: String,
}

#[tokio::test]
async fn create_event_works() {
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

    // Arrange - create the habit
    let habit = serde_json::json!({"name": "daily math practice", "description": "Learn from Linear Algebra Done Right book"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create an event for the previously created user and habit
    let event = serde_json::json!({
        "habit": "daily math practice",
        "date_time": "09-05-2023"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token)
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());
}

#[tokio::test]
async fn create_event_returns_400_when_fields_are_not_available() {
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

    // Arrange - event without name
    let event = serde_json::json!({
        "username": "djacota",
        "date_time": "09-05-2023"
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(400, response.status().as_u16());

    // Arrange event without date_time
    let event = serde_json::json!({
        "username": "djacota",
        "name": "add_bad_request_test",
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token)
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(400, response.status().as_u16());
}

#[tokio::test]
async fn event_requests_missing_authorization_are_rejected() {
    // Arrange
    let address = spawn_app();

    let event = serde_json::json!({
        "habit": "daily math practice",
        "date_time": "09-05-2023"
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn event_requests_with_invalid_credentials_are_rejected() {
    // Arrange
    let address = spawn_app();

    let event = serde_json::json!({
        "habit": "daily math practice",
        "date_time": "09-05-2023"
    });

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth("JWT_Random")
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
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
async fn delete_event_works() {
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
    let habit = serde_json::json!({"name": "daily stretch", "description": "at least 10 minutes"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create an event for the previously created user and habit
    let event = serde_json::json!({
        "habit": "daily stretch",
        "date_time": "11-25-2023"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to create a new event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

    // Act - get all the events
    let response_events = reqwest::Client::new()
        .get(&format!("{}/calendar/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the events.");

    // Assert
    assert!(response_events.status().is_success());
    let calendar: Calendar = response_events.json::<Calendar>().await.unwrap();
    assert_eq!(1, calendar.events.len());

    let response_event = &calendar.events[0];
    assert_eq!("daily stretch", response_event.habit);
    assert_eq!("11-25-2023", response_event.date_time);

    // Act - delete event
    let response_event = reqwest::Client::new()
        .delete(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to delete event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

    // Act - get all the events
    let response_events = reqwest::Client::new()
        .get(&format!("{}/calendar/daily stretch", &address))
        .bearer_auth(jwt.token)
        .send()
        .await
        .expect("Failed the get all the events.");

    // Assert
    assert!(response_events.status().is_success());
    let calendar: Calendar = response_events.json::<Calendar>().await.unwrap();
    assert!(calendar.events.is_empty());
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create another habit
    let habit = serde_json::json!({"name": "daily coffee", "description": "COFFEE!!"});

    // Act
    let response = reqwest::Client::new()
        .post(&format!("{}/habit", &address))
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create an event for the previously created user and habit
    let event = serde_json::json!({
        "habit": "daily stretch",
        "date_time": "11-25-2023"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to create a new event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

    // Act - delete habit
    let response_habit = reqwest::Client::new()
        .delete(&format!("{}/habit/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed to delete habit.");

    // Assert
    assert!(response_habit.status().is_success());
    assert_eq!(Some(0), response_habit.content_length());

    // Act - get all the habits
    let response_habits = reqwest::Client::new()
        .get(&format!("{}/habit", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habits.status().is_success());
    let habits: Vec<Habit> = response_habits.json::<Vec<Habit>>().await.unwrap();
    assert_eq!(1, habits.len());
    assert_eq!("daily coffee", habits[0].name);

    // Act - get all the events
    let response_events = reqwest::Client::new()
        .get(&format!("{}/calendar/daily stretch", &address))
        .bearer_auth(jwt.token)
        .send()
        .await
        .expect("Failed the get all the events.");

    // Assert
    assert_eq!(StatusCode::NOT_FOUND, response_events.status());
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Arrange - create an event for the previously created user and habit
    let event = serde_json::json!({
        "habit": "daily stretch",
        "date_time": "2023-11-25T12:12:12.0000Z"
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to create a new event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

    // Arrange - prepare habit to be edited
    let habit = serde_json::json!({
        "name": "daily yoga",
        "description": "Check Yoga With Adriene",
    });

    // Act - edit habit
    let response_habit = reqwest::Client::new()
        .put(&format!("{}/habit/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert!(response_habit.status().is_success());
    assert_eq!(Some(0), response_habit.content_length());

    // Act - get all the events
    let response_events = reqwest::Client::new()
        .get(&format!("{}/calendar/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the events.");

    // Assert
    assert_eq!(StatusCode::NOT_FOUND, response_events.status());

    // Act - get all the events for the updated habit
    let response_events = reqwest::Client::new()
        .get(&format!("{}/calendar/daily yoga", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the events.");

    // Assert
    assert!(response_events.status().is_success());
    let calendar: Calendar = response_events.json::<Calendar>().await.unwrap();
    assert_eq!(1, calendar.events.len());
    let response_event = &calendar.events[0];
    assert_eq!("daily yoga", response_event.habit);
    assert_eq!("2023-11-25T12:12:12.0000Z", response_event.date_time);

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
    assert_eq!("Pending", habits[0].state);
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - edit habit
    let response_habit = reqwest::Client::new()
        .put(&format!("{}/habit/daily stretch", &address))
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
        .put(&format!("{}/habit/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(404, response_habit.status().as_u16());
}

#[tokio::test]
async fn event_status_is_done_when_event_is_created_today() {
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());
    let utc_time = Utc::now();

    // Arrange - create an event for the previously created user and habit
    let event = serde_json::json!({
        "habit": "daily stretch",
        "date_time": utc_time.to_rfc3339(),
    });

    // Act
    let response_event = reqwest::Client::new()
        .post(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to create a new event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

    // Act - get all the habits
    let response_habits = reqwest::Client::new()
        .get(&format!("{}/habit", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habits.status().is_success());
    let habits: Vec<Habit> = response_habits.json::<Vec<Habit>>().await.unwrap();
    assert_eq!(1, habits.len());
    assert_eq!("daily stretch", habits[0].name);
    assert_eq!("Done", habits[0].state);

    // Act - delete the today's event
    let response_event = reqwest::Client::new()
        .delete(&format!("{}/event", &address))
        .bearer_auth(jwt.token.clone())
        .json(&event)
        .send()
        .await
        .expect("Failed to delete the event.");

    // Assert
    assert!(response_event.status().is_success());
    assert_eq!(Some(0), response_event.content_length());

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
    assert_eq!("daily stretch", habits[0].name);
    assert_eq!("Pending", habits[0].state);
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - get habit details
    let response_habit = reqwest::Client::new()
        .get(&format!("{}/habit/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed the get all the habits.");

    // Assert
    assert!(response_habit.status().is_success());
    let habit_details: HabitDetails = response_habit.json::<HabitDetails>().await.unwrap();
    assert_eq!("daily stretch", habit_details.name);
    assert_eq!("daily at 08:00", habit_details.description);
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
        .bearer_auth(jwt.token.clone())
        .json(&habit)
        .send()
        .await
        .expect("Failed to create a new habit.");

    // Assert
    assert!(response.status().is_success());

    // Act - get habit details
    let response_habit = reqwest::Client::new()
        .get(&format!("{}/habit/daily stretch", &address))
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
        .get(&format!("{}/habit/daily stretch", &address))
        .bearer_auth(jwt.token.clone())
        .send()
        .await
        .expect("Failed to edit habit.");

    // Assert
    assert_eq!(404, response_habit.status().as_u16());
}

// launch the server as a background task
fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");

    // We retrieve the port assigned to us by the OS
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::open_in_memory().unwrap();

    let server = run(listener, conn).expect("Failed to bind address");
    let _ = tokio::spawn(server);

    // We return the application address to the caller
    format!("http://127.0.0.1:{}", port)
}
