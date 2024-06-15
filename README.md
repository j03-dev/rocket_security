# Rocket Security
Jwt implementation for rocket

### Example
```rust
use crate::AppState;

use super::custome_response::*;

use models::User as UserModel;
use rocket_security::{create_new_token, hash, Auth, RegisteredClaims};

use rocket::State;
use rusql_alchemy::prelude::*;
use serde::Deserialize;

const ONE_WEEK: u64 = ((3600 * 24) * 7) as u64;

#[derive(Deserialize, Clone)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub verification: String,
}

#[post("/", format = "json", data = "<new_user>")]
pub async fn register(new_user: Json<NewUser>, app_state: &State<AppState>) -> Response {
    let conn = app_state.conn.clone();
    if new_user.password == new_user.verification
        && UserModel::create(
            kwargs!(
                username = new_user.username,
                email = new_user.email,
                password = hash(&new_user.password)
            ),
            &conn,
        )
        .await
    {
        Ok(Custom(
            Status::Created,
            json!({ "message": "User created successfully" }),
        ))
    } else {
        Err(Custom(
            Status::BadRequest,
            json!({ "message": "User is alredy exist or password is not match" }),
        ))
    }
}

#[derive(Deserialize)]
pub struct Credential {
    pub email: String,
    pub password: String,
}

#[post("/auth", format = "json", data = "<cred>")]
pub async fn authentication(cred: Json<Credential>, app_state: &State<AppState>) -> Response {
    let conn = app_state.conn.clone();
    if let Some(user) = UserModel::get(
        kwargs!(email = cred.email, password = hash(&cred.password)),
        &conn,
    )
    .await
    {
        let claims = RegisteredClaims {
            subject: Some(user.id.to_string()),
            expiration: Some(ONE_WEEK),
            ..Default::default()
        };
        let token = create_new_token(claims).unwrap();
        Ok(Custom(Status::Ok, json!({"user": user, "token": token})))
    } else {
        Err(Custom(
            Status::Unauthorized,
            json!({ "message": "email or password is invalid" }),
        ))
    }
}

#[get("/")]
pub async fn retrieve(auth: Auth, app_state: &State<AppState>) -> Response {
    let conn = app_state.conn.clone();
    let id: i32 = auth.subject.parse().unwrap();
    if let Some(user) = UserModel::get(kwargs!(id = id), &conn).await {
        Ok(Custom(Status::Ok, json!(user)))
    } else {
        Err(Custom(
            Status::NotFound,
            json!({ "message": "User not found" }),
        ))
    }
}
```
