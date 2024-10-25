use actix_web::{
    web::{self, Bytes},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::env;

#[derive(Clone)]
struct AppState {
    api_key: String,
    signing_secret: String,
    user_group: String,
}

fn verify_hmac(timestamp: &str, body: &str, signature: &str, secret: &str) -> bool {
    // Set secret
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    let content = format!("v0:{}:{}", timestamp, body);
    mac.update(content.as_bytes());
    let signature_bytes = hex::decode(&signature[3..]).unwrap();
    mac.verify((&signature_bytes[..]).into()).is_ok()
}

async fn get_current_group_members(api_key: &str, user_group: &str) -> Vec<String> {
    let client = reqwest::Client::new();
    let res = client
        .get(format!(
            "https://slack.com/api/usergroups.users.list?usergroup={}",
            user_group
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    v["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect()
}

async fn update_users(api_key: &str, user_group: &str, users: Vec<String>) {
    let client = reqwest::Client::new();
    let res = client
        .post("https://slack.com/api/usergroups.users.update")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&serde_json::json!({
            "usergroup": user_group,
            "users": users,
        }))
        .send()
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    if !v["ok"].as_bool().unwrap() {
        println!("{v}");
        panic!("Failed to update users");
    }
}

async fn index(body: Bytes, req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let signature = match req.headers().get("X-Slack-Signature") {
        Some(s) => s,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let timestamp = match req.headers().get("X-Slack-Request-Timestamp") {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let signature = signature.to_str().unwrap();
    let timestamp = timestamp.to_str().unwrap();
    println!("Signature: {}", signature);
    println!("Timestamp: {}", timestamp);
    let body = std::str::from_utf8(&body).unwrap();
    println!("Body: {}", body);
    if verify_hmac(timestamp, body, signature, &data.signing_secret) {
        let v: Value = serde_json::from_str(body).unwrap();
        if v.get("challenge").is_some() {
            let challenge = v["challenge"].as_str().unwrap().to_string();
            return HttpResponse::Ok().body(challenge);
        }
        // Get events
        let event = match v["event"].as_object() {
            Some(e) => e,
            None => return HttpResponse::BadRequest().finish(),
        };
        let event_type = match event["type"].as_str() {
            Some(t) => t,
            None => return HttpResponse::BadRequest().finish(),
        };
        if event_type != "team_join" {
            return HttpResponse::BadRequest().finish();
        }
        let user = match event["user"].as_object() {
            Some(u) => u,
            None => return HttpResponse::BadRequest().finish(),
        };
        match user["is_bot"].as_bool() {
            None => return HttpResponse::BadRequest().finish(),
            Some(true) => return HttpResponse::Ok().finish(),
            Some(false) => (),
        };
        let user_id = match user["id"].as_str() {
            Some(u) => u,
            None => return HttpResponse::BadRequest().finish(),
        };
        let mut users_in_group = get_current_group_members(&data.api_key, &data.user_group).await;
        if !users_in_group.contains(&user_id.to_string()) {
            return HttpResponse::Ok().finish();
        }
        users_in_group.retain(|x| x != user_id);
        update_users(&data.api_key, &data.user_group, users_in_group).await;
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let data = AppState {
        api_key: env::var("SLACK_API_KEY").unwrap(),
        signing_secret: env::var("SLACK_SIGNING_SECRET").unwrap(),
        user_group: env::var("SLACK_USER_GROUP").unwrap(),
    };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(data.clone()))
            .route("/", web::post().to(index))
    })
    .bind("0.0.0.0:8080")
    .unwrap()
    .run()
    .await
}