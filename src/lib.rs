use crypto::{digest::Digest, sha3};
use hmac::digest::{core_api::CoreWrapper, KeyInit};
use hmac::{Hmac, HmacCore};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;
use sha2::Sha256;

pub use jwt::RegisteredClaims;

pub fn hash(input: &str) -> String {
    let mut hasher = sha3::Sha3::sha3_256();
    hasher.input_str(input);
    hasher.result_str()
}

fn get_secret_key() -> Vec<u8> {
    let secret_key = std::env::var("SECRET_KEY").expect("Secret key must be set");
    secret_key.chars().map(|s| s as u8).collect()
}

fn signe_key() -> CoreWrapper<HmacCore<Sha256>> {
    let secret_key = get_secret_key();
    Hmac::<Sha256>::new_from_slice(&secret_key[..]).unwrap()
}

fn read_token(token_str: &str) -> Result<String, jwt::Error> {
    let token = Token::<Header, RegisteredClaims, _>::parse_unverified(token_str)?;

    token
        .verify_with_key(&signe_key())
        .and_then(|token_verify| match token_verify.claims().clone().subject {
            Some(subject) => Ok(subject),
            None => Err(jwt::Error::NoClaimsComponent),
        })
        .map_or(Err(jwt::Error::InvalidSignature), Ok)
}

pub fn create_new_token(claims: RegisteredClaims) -> Result<String, jwt::Error> {
    let new_token = Token::new(Header::default(), claims).sign_with_key(&signe_key())?;
    Ok(new_token.as_str().to_string())
}

#[derive(Clone)]
pub struct Auth {
    pub subject: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Auth {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let t = request.headers().get("Authorization").next();
        println!("{t:#?}");

        request
            .headers()
            .get("Authorization")
            .next()
            .and_then(|token| {
                if token == format!("Bearer {token}") {
                    match read_token(token) {
                        Ok(subject) => Some(Auth { subject }),
                        Err(err) => {
                            eprintln!("{err}");
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .map_or(Outcome::Error((Status::Unauthorized, ())), |auth| {
                Outcome::Success(auth)
            })
    }
}
