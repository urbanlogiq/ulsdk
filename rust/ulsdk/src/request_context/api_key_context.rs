// Copyright (c), CommunityLogiq Software

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, SECRET_KEY_LENGTH};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use url::form_urlencoded;
use uuid::Uuid;

use crate::error::Error;
use crate::keys::Key;
use crate::request_context::{
    get_endpoint, Environment, File, ParamMap, Region, RequestContext, DELAYS,
};

const REQUEST_TYPE: &str = "ul1_request";
const SIGNATURE_V1: &str = "UL1-ED25519";
const HEADER_AUTHORIZATION: &str = "authorization";
const HEADER_X_UL_DATE: &str = "x-ul-date";
const HEADER_CONTENT_TYPE: &str = "content-type";
const SIGNED_HEADERS: &[&str] = &[HEADER_X_UL_DATE];

#[derive(Clone)]
pub struct ApiKeyContext {
    environment: Environment,
    key: Key,
}

impl ApiKeyContext {
    pub fn new(key: Key, environment: Environment) -> Self {
        Self { environment, key }
    }

    pub fn user_id(&self) -> Uuid {
        self.key.user_id()
    }
}

fn canonicalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }

    if !path.starts_with('/') {
        return format!("/{}", path);
    }

    path.to_owned()
}

fn canonicalize_query_string(query: &mut [(String, String)]) -> String {
    if query.is_empty() {
        return String::new();
    }

    query.sort_by(|a, b| a.0.cmp(&b.0));

    let components = query
        .iter()
        .filter(|(k, _)| k != "X-UL-Signature")
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>();
    components.join("&")
}

fn canonicalize_headers(signed_headers: &[&str], headers: &HeaderMap) -> Result<String, Error> {
    let mut sorted_signed_headers = signed_headers
        .iter()
        .map(|x| x.to_lowercase())
        .collect::<Vec<_>>();
    sorted_signed_headers.sort();

    let canonical_header_parts = sorted_signed_headers
        .into_iter()
        .flat_map(|v| {
            match HeaderName::from_lowercase(v.as_bytes()).map_err(|e| Error::from(e.to_string())) {
                Ok(header_name) => {
                    if let Some(value) = headers.get(header_name) {
                        match value.to_str().map_err(|e| Error::from(e.to_string())) {
                            Ok(value) => Some(Ok(format!("{}:{}", v, value.trim()))),
                            Err(e) => Some(Err(e)),
                        }
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(canonical_header_parts.join("\n"))
}

fn hash(slice: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    hex::encode(hasher.finalize())
}

fn canonicalize_request(
    method: &str,
    path: &str,
    query: &mut [(String, String)],
    headers: &HeaderMap,
    signed_headers: &[&str],
    body: &[u8],
) -> Result<(String, String), Error> {
    let canonical_path = canonicalize_path(path);
    let canonical_query_string = canonicalize_query_string(query);
    let canonical_headers = canonicalize_headers(signed_headers, headers)?;
    let signed_headers = signed_headers.to_vec().join(";");

    let s = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        canonical_path,
        canonical_query_string,
        canonical_headers,
        signed_headers,
        hash(body)
    );

    Ok((hash(s.as_bytes()), signed_headers))
}

fn generate_auth_header(
    key: &Key,
    method: &str,
    path: &str,
    query: &mut [(String, String)],
    headers: &mut HeaderMap,
    body: &[u8],
) -> Result<String, Error> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    headers.insert(
        HeaderName::from_static(HEADER_X_UL_DATE),
        HeaderValue::from_str(&ts).unwrap(),
    );

    let (request_hash, signed_headers) =
        canonicalize_request(method, path, query, headers, SIGNED_HEADERS, body)?;

    let scope = format!("{}/{}/{}/{}", key.user_id(), ts, key.region(), REQUEST_TYPE);
    let signing_string = format!("{}\n{}\n{}", SIGNATURE_V1, scope, request_hash);

    let secret_key = key.secret_key()[0..SECRET_KEY_LENGTH].try_into().unwrap();
    let keypair = SigningKey::from_bytes(secret_key);
    let signature: Signature = keypair.sign(signing_string.as_bytes());
    let signature = hex::encode(signature.to_bytes());

    Ok(format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        SIGNATURE_V1,
        key.access_key(),
        scope,
        signed_headers,
        signature
    ))
}

#[async_trait]
impl RequestContext for ApiKeyContext {
    fn region(&self) -> Region {
        self.key.region()
    }

    fn environment(&self) -> Environment {
        self.environment
    }

    async fn get(
        &self,
        path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = get_endpoint(self.key.region(), self.environment, path);
        let client = reqwest::Client::new();
        let mut response = None;

        let params = params.unwrap_or_default();

        let mut query = Vec::new();
        params
            .iter()
            .for_each(|(k, v)| query.push((k.to_owned(), v.to_owned())));

        let mut headers = headers.unwrap_or_default();
        let auth_header =
            generate_auth_header(&self.key, "GET", path, &mut query, &mut headers, &[])?;

        headers.insert(
            HeaderName::from_static(HEADER_AUTHORIZATION),
            HeaderValue::from_str(&auth_header).unwrap(),
        );

        for delay in DELAYS {
            let r = client
                .get(&endpoint)
                .headers(headers.clone())
                .query(&params)
                .send()
                .await?;

            if r.status().is_server_error() {
                response = Some(r);
                sleep(Duration::from_millis(*delay)).await;
            } else {
                response = Some(r);
                break;
            }
        }

        let response = if let Some(r) = response {
            r
        } else {
            return Err(Error::Unclassified("No error from endpoint".into()));
        };

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint.to_owned(),
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                unsafe { std::str::from_utf8_unchecked(&bytes) }.to_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::ReqwestError)
            .map(|b| b.to_vec())
    }

    async fn put(
        &self,
        path: &str,
        body: Bytes,
        mimetype: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = get_endpoint(self.key.region(), self.environment, path);
        let client = reqwest::Client::new();
        let mut response = None;

        let params = params.unwrap_or_default();

        let mut query = Vec::new();
        params
            .iter()
            .for_each(|(k, v)| query.push((k.to_owned(), v.to_owned())));

        let mut headers = headers.unwrap_or_default();
        headers.insert(
            HeaderName::from_static(HEADER_CONTENT_TYPE),
            HeaderValue::from_str(mimetype).unwrap(),
        );

        let auth_header =
            generate_auth_header(&self.key, "PUT", path, &mut query, &mut headers, &body)?;

        headers.insert(
            HeaderName::from_static(HEADER_AUTHORIZATION),
            HeaderValue::from_str(&auth_header).unwrap(),
        );

        for delay in DELAYS {
            let r = client
                .put(&endpoint)
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await?;

            if r.status().is_server_error() {
                response = Some(r);
                sleep(Duration::from_millis(*delay)).await;
            } else {
                response = Some(r);
                break;
            }
        }

        let response = if let Some(r) = response {
            r
        } else {
            return Err(Error::Unclassified("No error from endpoint".into()));
        };

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint.to_owned(),
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                unsafe { std::str::from_utf8_unchecked(&bytes) }.to_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::ReqwestError)
            .map(|b| b.to_vec())
    }

    async fn post(
        &self,
        path: &str,
        body: Bytes,
        mimetype: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = get_endpoint(self.key.region(), self.environment, path);
        let client = reqwest::Client::new();
        let mut response = None;

        let params = params.unwrap_or_default();

        let mut query = Vec::new();
        params
            .iter()
            .for_each(|(k, v)| query.push((k.to_owned(), v.to_owned())));

        let mut headers = headers.unwrap_or_default();
        headers.insert(
            HeaderName::from_static(HEADER_CONTENT_TYPE),
            HeaderValue::from_str(mimetype).unwrap(),
        );

        let auth_header =
            generate_auth_header(&self.key, "POST", path, &mut query, &mut headers, &body)?;

        headers.insert(
            HeaderName::from_static(HEADER_AUTHORIZATION),
            HeaderValue::from_str(&auth_header).unwrap(),
        );

        for delay in DELAYS {
            let r = client
                .post(&endpoint)
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await?;

            if r.status().is_server_error() {
                response = Some(r);
                sleep(Duration::from_millis(*delay)).await;
            } else {
                response = Some(r);
                break;
            }
        }

        let response = if let Some(r) = response {
            r
        } else {
            return Err(Error::Unclassified("No error from endpoint".into()));
        };

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint.to_owned(),
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                unsafe { std::str::from_utf8_unchecked(&bytes) }.to_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::ReqwestError)
            .map(|b| b.to_vec())
    }

    async fn upload(&self, _path: &str, _files: Vec<File>) -> Result<(), Error> {
        todo!()
    }

    async fn delete(
        &self,
        path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = get_endpoint(self.key.region(), self.environment, path);
        let client = reqwest::Client::new();
        let mut response = None;

        let params = params.unwrap_or_default();

        let mut query = Vec::new();
        params
            .iter()
            .for_each(|(k, v)| query.push((k.to_owned(), v.to_owned())));

        let mut headers = headers.unwrap_or_default();
        let auth_header =
            generate_auth_header(&self.key, "GET", path, &mut query, &mut headers, &[])?;

        headers.insert(
            HeaderName::from_static(HEADER_AUTHORIZATION),
            HeaderValue::from_str(&auth_header).unwrap(),
        );

        for delay in DELAYS {
            let r = client
                .delete(&endpoint)
                .headers(headers.clone())
                .query(&params)
                .send()
                .await?;

            if r.status().is_server_error() {
                response = Some(r);
                sleep(Duration::from_millis(*delay)).await;
            } else {
                response = Some(r);
                break;
            }
        }

        let response = if let Some(r) = response {
            r
        } else {
            return Err(Error::Unclassified("No error from endpoint".into()));
        };

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint.to_owned(),
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                unsafe { std::str::from_utf8_unchecked(&bytes) }.to_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::ReqwestError)
            .map(|b| b.to_vec())
    }
}
