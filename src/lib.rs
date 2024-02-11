
use base64::{Engine as _, engine::general_purpose};
use biscuit::{
    jws::{
        Header, RegisteredHeader}, 
    Empty 
};
use chrono::Utc;
use json::{JsonValue, object};
use ring::{
    rand, rsa, signature
};
use std::fs;

pub struct Config {
    environment: String,
    user_type: String,
    user: String,
}
impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        let environment = args[1].clone();
        let user_type = args[2].clone();
        let user = args[3].clone();
        Ok(Config {
            environment,
            user_type,
            user,
        })
    }
}

pub fn file_path_builder(c: &Config) -> String {
    let mut path = String::new();
    path.push_str(&c.environment);
        path.push_str("_");
    path.push_str(&c.user_type);
        path.push_str("_");
    path.push_str(&c.user);
    path.push_str(".json");
    return path;
}

pub fn sig_generator(c: Config) {
    // Builds path to creds file and prints value
    let path = file_path_builder(&c);
    println!("Attempting to use: {}", path);
    // Reads file to string, parses JSON, reads privateKey and formats it
    let credentials = fs::read_to_string(path).unwrap();
    let json_creds: JsonValue = json::parse(&credentials).unwrap();
    let key: String = json_creds["privateKey"].clone().to_string()
        .replace("\n", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("=", "");
    println!("Private key: {}", &key);

    // Decodes the privateKey to a byte array
    //let s = String::from("UGxlYXNlIGJlIHBhdGllbnQsIEltIHN0aWxsIGxlYXJuaW5n");
    //let bytes = general_purpose::STANDARD
    //    .decode(s)
    //    .unwrap();
    //println!("Example decoding: {:?}", bytes);
    
    let decoded_key = general_purpose::STANDARD
        .decode(key)
        .unwrap();
    println!("Private key as byte array: {:?}", decoded_key);

    // Creates the header and body
    let json_header = object! {
        "alg" => "RS256"
    };
    let serialized_header = json_header.dump();

    let name: &str = &json_creds["name"].to_string();
    let organization: &str = &json_creds["organization"].to_string();
    let utc = Utc::now().to_rfc3339();
    let json_body = object! {
        "name" => name,
        "organization" => organization,
        "dateTime" => utc
    };
    let serialized_body = json_body.dump();

    println!("Header: {}", serialized_header);
    println!("Body: {}", serialized_body);

    // Builds the signature
    // Header component
    let header = Header::<Empty>::from(RegisteredHeader {
        algorithm: biscuit::jwa::SignatureAlgorithm::RS256,
        ..Default::default()
    });
    // The Signable requires a payload byte array
    let body_vec: Vec<char> = serialized_body.chars().collect();
    let mut body_vec_output = Vec::new();
    for i in body_vec {
       body_vec_output.push(i as u8) 
    }

    let key_pair = rsa::KeyPair::from_der(&decoded_key).unwrap();
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, &body_vec_output, &mut signature).unwrap();
    let public_key = signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256, 
        json_creds["privateKey"].clone().to_string()
    );
    println!("Public key: {:#?}", public_key);

}

pub fn encoder() {
    let mut buf = String::new();
    general_purpose::STANDARD.encode_string("Please be patient, Im still learning", &mut buf);
    println!("First encoded part: {}", buf);
    general_purpose::STANDARD.encode_string("Rust is starting to make a little bit of sense though", &mut buf);
    println!("Second encoded part: {}", buf);
    println!("/////////////////////////////////////");

}
