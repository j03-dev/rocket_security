use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;

use anyhow::{Context, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub aud: Option<String>,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub nbf: Option<usize>,
}

impl Default for Claims {
    fn default() -> Self {
        Self {
            sub: "anonymous".to_owned(),
            exp: 1,
            aud: None,
            iat: None,
            iss: None,
            nbf: None,
        }
    }
}

pub fn generate_jwt(claims: Claims) -> Result<String> {
    let secret_key = std::env::var("SECRET_KEY")?;
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(claims.exp as i64))
        .context("Failed to calculate expiration time for JWT claims")?
        .timestamp() as usize;

    let claims = Claims {
        exp: expiration,
        ..claims
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_bytes()),
    )?;

    Ok(token)
}

fn verify_jwt<T: for<'de> Deserialize<'de>>(token: &str) -> Result<T> {
    let secret_key = std::env::var("SECRET_KEY")?;
    let token_data = decode::<T>(
        token,
        &DecodingKey::from_secret(secret_key.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;

    Ok(token_data.claims)
}

#[derive(Debug)]
pub enum AuthError {
    MissingOrInvalidHeader,
    InvalidToken,
}

#[derive(Clone)]
pub struct Auth {
    pub subject: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Auth {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        const BEARER_PREFIX: &str = "Bearer ";
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            if let Some(token) = auth_header.strip_prefix(BEARER_PREFIX) {
                return match verify_jwt::<Claims>(&token) {
                    Ok(claims) => Outcome::Success(Auth {
                        subject: claims.sub,
                    }),
                    Err(_) => Outcome::Error((Status::Unauthorized, AuthError::InvalidToken)),
                };
            }
        }
        Outcome::Error((Status::Unauthorized, AuthError::MissingOrInvalidHeader))
    }
}
