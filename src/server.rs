use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::Request,
    middleware::{self, Next},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Serialize, Clone)]
struct PublicKeys {
    public_x25519: String,
    public_ed25519: String,
}

#[tokio::main]
async fn main() {
    let x25519_server_secret = EphemeralSecret::random();
    let x25519_server_public = PublicKey::from(&x25519_server_secret);
    let base64ed_x25519 = general_purpose::STANDARD.encode(x25519_server_public);

    let mut csprng = OsRng;
    let ed25519_server_secret: SigningKey = SigningKey::generate(&mut csprng);
    let ed25519_server_public: VerifyingKey = ed25519_server_secret.verifying_key();
    let base64ed_ed25519 = general_purpose::STANDARD.encode(ed25519_server_public);

    let pub_keys = PublicKeys {
        public_x25519: base64ed_x25519,
        public_ed25519: base64ed_ed25519,
    };

    let app = Router::new()
        .route("/api/public-keys", get(public_keys).with_state(pub_keys))
        .nest(
            "/comms",
            Router::new()
                .route("/placeholder", get(placeholder))
                .layer(middleware::from_fn(placeholder_middlware)),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn public_keys(State(state): State<PublicKeys>) -> Json<PublicKeys> {
    Json(state)
}

async fn placeholder() -> &'static str {
    "placeholder"
}

async fn placeholder_middlware(req: Request<Body>, next: Next) {
    println!("middleware things");
}