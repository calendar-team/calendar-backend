use calendar_backend::run;

#[tokio::test]
async fn create_event_works() {
    // Arrange
    spawn_app();

    let client = reqwest::Client::new();
    let event = serde_json::json!({
        "username": "djacota",
        "name": "write_integration_tests",
        "calendar_id": "djacota",
        "date_time": "09-05-2023"
    });

    // Act
    let response = client
        .post("http://127.0.0.1:8080/event")
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}

#[tokio::test]
async fn create_event_missing_fields_return_400_bad_request() {
    // Arrange event without name
    spawn_app();

    let event = serde_json::json!({
        "username": "djacota",
        "calendar_id": "djacota",
        "date_time": "09-05-2023"
    });

    // Act
    let response = reqwest::Client::new()
        .post("http://127.0.0.1:8080/event")
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
        "calendar_id": "djacota"
    });

    // Act
    let response = reqwest::Client::new()
        .post("http://127.0.0.1:8080/event")
        .json(&event)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(400, response.status().as_u16());
}

// launch the server as a background task
fn spawn_app() {
    let server = run().expect("Failed to bind address");
    let _ = tokio::spawn(server);
}
