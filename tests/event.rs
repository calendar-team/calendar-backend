use calendar_backend::run;
use std::net::TcpListener;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Jwt {
    token: String,
}

#[tokio::test]
async fn create_event_works() {
    // Arrange - create the user
    let address = spawn_app();
    let username = "djacota";
    let password = "password";

    let user = serde_json::json!({
        "username": username,
        "password": password,
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

    // Arrange - create an event for the user previously created
    let event = serde_json::json!({
        "username": "djacota",
        "name": "write_integration_tests",
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

    let user = serde_json::json!({
        "username": username,
        "password": password,
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
        "username": "djacota",
        "name": "implement_basic_authentication",
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
        "username": "djacota",
        "name": "implement_basic_authentication",
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

    let user = serde_json::json!({
        "username": username,
        "password": password,
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

// launch the server as a background task
fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");

    // We retrieve the port assigned to us by the OS
    let port = listener.local_addr().unwrap().port();

    let server = run(listener).expect("Failed to bind address");
    let _ = tokio::spawn(server);

    // We return the application address to the caller
    format!("http://127.0.0.1:{}", port)
}
