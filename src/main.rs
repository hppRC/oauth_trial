use reqwest::header::*;
use chrono::Utc;

#[derive(Clone,Debug)]
struct RequestToken {
    oauth_token: String,
    oauth_token_secret: String,
    oauth_callback_confirmed: String,
}

fn from_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(val) => val,
        Err(err) => {
            println!("{}: {}", err, name);
            std::process::exit(1);
        }
    }
}

fn create_oauth_signature(
    http_method: &str,
    endpoint: &str,
    oauth_consumer_secret: &str,
    oauth_token_secret: &str,
    params: &std::collections::HashMap<&str, &str>
) -> String {
    "".to_string()
}

fn get_request_header(endpoint: &str) -> String {
    let oauth_consumer_key: &str= &from_env("CONSUMERKEY");
    let oauth_consumer_secret: &str= &from_env("CONSUMERSECRET");
    let oauth_nonce: &str = &format!("nonce{}", Utc::now().timestamp());
    let oauth_callback: &str =  "http://127.0.0.1";
    let oauth_signature_method: &str = "HMAC-SHA1";
    let oauth_timestamp: &str = &format!("{}", Utc::now().timestamp());
    let oauth_version: &str = "1.0";

    let mut params: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    params.insert("oauth_nonce", oauth_nonce);
    params.insert("oauth_callback", oauth_callback);
    params.insert("oauth_signature_method", oauth_signature_method);
    params.insert("oauth_timestamp", oauth_timestamp);
    params.insert("oauth_version", oauth_version);
    params.insert("oauth_consumer_key", oauth_consumer_key);

    let oauth_signature: &str = &create_oauth_signature(
        "POST",
        &endpoint,
        oauth_consumer_secret,
        "",
        &params
    );

    "".to_string()
}


fn get_request_token() -> RequestToken {
    let endpoint = "https://api.twitter.com/oauth/request_token";
    let header_auth = get_request_header(endpoint);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, header_auth.parse().unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));

    RequestToken {
        oauth_token: "".to_string(),
        oauth_token_secret: "".to_string(),
        oauth_callback_confirmed: "".to_string()
    }
}

fn main() {
    let req = get_request_token();

    println!("{:?}", req);
}
