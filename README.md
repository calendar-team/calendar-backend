# calendar-backend
The backend for the calendar app

## How to build and run
Start the server:
```sh 
cargo run
```
Make a request:
```sh
curl localhost:8080/calendar/myCalendar
```

## Deploy to K8S

We use a github actions workflow: [deployment_to_k8s.yml](./.github/workflows/deployment_to_k8s.yml) to deploy the app to K8S. The workflow is triggered every time a commit is merged on master and pushed to github.

Before the first deployment, a few secrets should be added on the repo:

1. `CONTAINER_REGISTRY_URL`, `CONTAINER_REGISTRY_USER`, and `CONTAINER_REGISTRY_PASSWORD` - the credentials for pushing to container registry
2. `JWT_KEY` - the JWT key that will be used to encrypt JWTs
3. `K8S_URL`, and `K8S_SECRET` - the credentials for deploying to K8S cluster
4. `R2_CREDENTIALS` - the credentials for uploading db backup to R2. The format should be:
```
{
    "bucket-name": "",
    "account-id": "",
    "access-key-id": "",
    "access-key-secret": "",
}
```
Details about each field cand be found in the [sqlite-to-r2](https://github.com/calendar-team/sqlite-to-r2) repo.

