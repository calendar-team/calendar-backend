# calendar-backend

The backend for the [calendar](https://calendar.aguzovatii.com).

## Getting started

1. Start the backend:
    ```sh
    cargo run
    ```
2. Start the [frontend](https://github.com/aguzovatii/calendar-frontend)
3. Open the app in browser: [localhost:3000](http://localhost:3000)

## Deploy to K8S

We use a github actions workflow: [deployment_to_k8s.yml](./.github/workflows/deployment_to_k8s.yml) to deploy the app to K8S. The workflow is triggered every time a commit is merged on master and pushed to github.

Before the first deployment, a few secrets should be added on the repo:

1. `CONTAINER_REGISTRY_URL`, `CONTAINER_REGISTRY_USER`, and `CONTAINER_REGISTRY_PASSWORD` - the credentials for pushing to container registry. The credentials can be found as part of `ghcr.io container registry credentials` secret in bitwarden.
2. `JWT_KEY` - the JWT key that will be used to encrypt JWTs. The format should be:

    ```
    {
        "jwt-key": ""
    }
    ```
3. `K8S_URL`, and `K8S_SECRET` - the credentials for deploying to K8S cluster.
    1. `K8S_URL` - set this to `https://<domain>:6443`
    2. `K8S_SECRET` - copy the whole yaml output from the following command:
       ```
       kubectl get secret continuous-deployment -oyaml
       ```
5. `R2_CREDENTIALS` - the credentials for uploading db backup to R2. The format should be:
    ```
    {
        "bucket-name": "",
        "account-id": "",
        "access-key-id": "",
        "access-key-secret": ""
    }
    ```
    Details about each field cand be found in the [sqlite-to-r2](https://github.com/calendar-team/sqlite-to-r2) repo.

