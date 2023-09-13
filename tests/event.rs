use calendar_backend::run;

#[tokio::test]
async fn create_event_works() {
    // Arrange
    spawn_app();

    let client = reqwest::Client::new();
    let event = serde_json::json!({
        "username": "djacota",
        "name": "write_integration_tests",
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

// launch the server as a background task
fn spawn_app() {
    let server = run().expect("Failed to bind address");
    let _ = tokio::spawn(server);
}
