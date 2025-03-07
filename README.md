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
4. `R2_CREDENTIALS` - the credentials for uploading db backup to R2. The format should be:
    ```
    {
        "bucket-name": "",
        "account-id": "",
        "access-key-id": "",
        "access-key-secret": ""
    }
    ```
    Details about each field cand be found in the [sqlite-to-r2](https://github.com/calendar-team/sqlite-to-r2) repo.

## DB migrations

Currently we do manual migrations in the db.

This means that each time the schema changes, we need to manually do it in the cluster.

Suppose we want to change the `habit` table in the following way:

<table>
<tr>
<th>Old schema</th>
<th>New schema</th>
</tr>
<tr>

<td>

```sql
CREATE TABLE habit (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    username    TEXT NOT NULL,
    UNIQUE (username, name),
    FOREIGN KEY (username) REFERENCES user (username) ON DELETE CASCADE ON UPDATE CASCADE
)
```
</td>

<td>

```sql
CREATE TABLE habit (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    username    TEXT NOT NULL,
    is_ad_hoc   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (username, name, is_ad_hoc),
    FOREIGN KEY (username) REFERENCES user (username) ON DELETE CASCADE ON UPDATE CASCADE
)
```
</td>

</tr>
</table>

Notice that we are adding a new column and changing the unique constraint.

Unfortunately, SQLite doesn't support changing the unique constraint.

To achieve this change in the live env, we need to apply the following workaround:

1. Stop the application: `kubectl -n calendar-backend edit deploy calendar-backend` and then change the `replicas` to 0
2. Deploy an image that contains the sqlite CLI:
   ```yaml
   kind: Deployment
   metadata:
     name: sqlite3-deployment
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: sqlite3
     template:
       metadata:
         labels:
           app: sqlite3
       spec:
         containers:
         - name: sqlite3-container
           image: alpine/sqlite:latest
           volumeMounts:
           - mountPath: /data
             name: sqlite-storage
           command: ["/bin/sh", "-c", "sleep infinity"]
         volumes:
         - name: sqlite-storage
           persistentVolumeClaim:
             claimName: calendar-backend-db
   ```
3. Create a new temporary table `new_habit` with the new schema.
4. Copy all the data from the `habit` table into `new_habit`: `INSERT INTO new_habit (id, name, description, username) SELECT id, name, description, username FROM habit;`
5. Drop the `habit` table: `DROP TABLE habit`
6. Rename the `new_habit` table to `habit`: `ALTER TABLE new_habit RENAME TO habit`
7. Delete the temporary deployment from step 2
8. Redeploy the backend

