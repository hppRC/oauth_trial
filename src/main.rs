use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::header::*;
use chrono::Utc;

const FRAGMENT: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_');


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
    let cs_encoded = utf8_percent_encode(oauth_consumer_secret, FRAGMENT);
    let ts_encoded = utf8_percent_encode(oauth_token_secret, FRAGMENT);
    let key: String = format!("{}&{}", cs_encoded, ts_encoded);

    let mut params: Vec<(&&str, &&str)> = params.into_iter().collect();
    params.sort();

    let param = params
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, FRAGMENT),
                utf8_percent_encode(v, FRAGMENT)
                )
            })
        .collect::<Vec<String>>()
        .join("&");

    let http_method_encoded = utf8_percent_encode(http_method, FRAGMENT);
    let endpoint_encoded = utf8_percent_encode(endpoint, FRAGMENT);
    let param_encoded = utf8_percent_encode(&param, FRAGMENT);

    let data = format!("{}&{}&{}", http_method_encoded, endpoint_encoded, param_encoded);

    let hash = hmacsha1::hmac_sha1(key.as_bytes(), data.as_bytes());
    base64::encode(&hash)
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

    format!(
        "OAuth oauth_nonce=\"{}\", oauth_callback=\"{}\", oauth_signature_method=\"{}\", oauth_timestamp=\"{}\", oauth_consumer_key=\"{}\", oauth_signature=\"{}\", oauth_version=\"{}\"",
        utf8_percent_encode(oauth_nonce, FRAGMENT),
        utf8_percent_encode(oauth_callback, FRAGMENT),
        utf8_percent_encode(oauth_signature_method, FRAGMENT),
        utf8_percent_encode(oauth_timestamp, FRAGMENT),
        utf8_percent_encode(oauth_consumer_key, FRAGMENT),
        utf8_percent_encode(oauth_signature, FRAGMENT),
        utf8_percent_encode(oauth_version, FRAGMENT),
    )
}


fn get_request_token() -> RequestToken {
    let endpoint = "https://api.twitter.com/oauth/request_token";
    let header_auth = get_request_header(endpoint);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, header_auth.parse().unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));

    let client = reqwest::Client::new();

    let res: String = client
        .post(endpoint)
        .headers(headers)
        .send()
        .unwrap()
        .text()
        .unwrap();

    let res_values: Vec<&str> = (&res)
        .split('&')
        .map(|s| s.split('=').collect::<Vec<&str>>()[1])
        .collect();

    RequestToken {
        oauth_token: res_values[0].to_string(),
        oauth_token_secret: res_values[1].to_string().to_string(),
        oauth_callback_confirmed: res_values[2].to_string(),
    }
}

fn main() {
    let req = get_request_token();

    println!("{:?}", req);
}
