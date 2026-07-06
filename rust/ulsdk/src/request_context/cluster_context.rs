// Copyright (c), CommunityLogiq Software

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

use crate::error::Error;
use crate::request_context::{File, ParamMap, RequestContext, DELAYS};
use crate::{Environment, Region};

const SVC_PREFIX: &str = "/v1/api/";

const HEADER_X_UL_USER_OID: &str = "x-ul-user-oid";
const HEADER_X_UL_USER_GROUPS: &str = "x-ul-user-groups";
const HEADER_X_UL_CORRELATION: &str = "x-ul-correlation";
const HEADER_CONTENT_TYPE: &str = "content-type";

pub struct ClusterContext {
    user_id: Uuid,
    groups: String,
    correlation_id: String,
}

impl ClusterContext {
    pub fn new(user_id: Uuid, groups: String, correlation_id: String) -> Self {
        Self {
            user_id,
            groups,
            correlation_id,
        }
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    fn base_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(HEADER_X_UL_USER_OID),
            HeaderValue::from_str(&self.user_id.to_string()).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(HEADER_X_UL_USER_GROUPS),
            HeaderValue::from_str(&self.groups).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(HEADER_X_UL_CORRELATION),
            HeaderValue::from_str(&self.correlation_id).unwrap(),
        );
        headers
    }

    fn route(&self, path: &str) -> Result<String, Error> {
        let rest = path
            .strip_prefix(SVC_PREFIX)
            .ok_or_else(|| Error::Unclassified(format!("invalid path: {}", path).into()))?;

        let (svc, remainder) = rest
            .split_once('/')
            .ok_or_else(|| Error::Unclassified(format!("invalid path: {}", path).into()))?;

        match svc {
            "ulv2" => Ok(format!(
                "http://ulv2.api.svc.cluster.local:8062/{}",
                remainder
            )),
            "uldirectory" => Ok(format!(
                "http://uldirectory.api.svc.cluster.local:8077/{}",
                remainder
            )),
            _ => Err(Error::Unclassified(
                format!("unknown service: {}", svc).into(),
            )),
        }
    }

    fn merge_headers(&self, extra: Option<HeaderMap>) -> HeaderMap {
        let mut headers = self.base_headers();
        if let Some(extra) = extra {
            headers.extend(extra);
        }
        headers
    }
}

#[async_trait]
impl RequestContext for ClusterContext {
    fn region(&self) -> Region {
        unimplemented!()
    }

    fn environment(&self) -> Environment {
        unimplemented!()
    }

    async fn get(
        &self,
        path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = self.route(path)?;
        let client = reqwest::Client::new();
        let headers = self.merge_headers(headers);
        let params = params.unwrap_or_default();
        let mut response = None;

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

        let response =
            response.ok_or_else(|| Error::Unclassified("No response from endpoint".into()))?;

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint,
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::Reqwest)
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
        let endpoint = self.route(path)?;
        let client = reqwest::Client::new();
        let mut headers = self.merge_headers(headers);
        headers.insert(
            HeaderName::from_static(HEADER_CONTENT_TYPE),
            HeaderValue::from_str(mimetype).unwrap(),
        );
        let params = params.unwrap_or_default();
        let mut response = None;

        for delay in DELAYS {
            let r = client
                .put(&endpoint)
                .headers(headers.clone())
                .query(&params)
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

        let response =
            response.ok_or_else(|| Error::Unclassified("No response from endpoint".into()))?;

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint,
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::Reqwest)
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
        let endpoint = self.route(path)?;
        let client = reqwest::Client::new();
        let mut headers = self.merge_headers(headers);
        headers.insert(
            HeaderName::from_static(HEADER_CONTENT_TYPE),
            HeaderValue::from_str(mimetype).unwrap(),
        );
        let params = params.unwrap_or_default();
        let mut response = None;

        for delay in DELAYS {
            let r = client
                .post(&endpoint)
                .headers(headers.clone())
                .query(&params)
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

        let response =
            response.ok_or_else(|| Error::Unclassified("No response from endpoint".into()))?;

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint,
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::Reqwest)
            .map(|b| b.to_vec())
    }

    async fn upload(&self, path: &str, files: Vec<File>) -> Result<Vec<u8>, Error> {
        let boundary = format!(
            "UL1-multipart-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let crlf = "\r\n";

        let mut body = Vec::new();

        for file in files {
            body.extend(b"--");
            body.extend(boundary.as_bytes());
            body.extend(crlf.as_bytes());

            let disposition_header = format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                file.name, file.name, file.mimetype
            );
            body.extend(disposition_header.as_bytes());
            body.extend(&file.data);
        }

        body.extend(b"--");
        body.extend(boundary.as_bytes());
        body.extend(b"--");

        let mimetype = format!("multipart/form-data; boundary=\"{}\"", boundary);

        self.post(path, body.into(), &mimetype, None, None).await
    }

    async fn delete(
        &self,
        path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let endpoint = self.route(path)?;
        let client = reqwest::Client::new();
        let headers = self.merge_headers(headers);
        let params = params.unwrap_or_default();
        let mut response = None;

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

        let response =
            response.ok_or_else(|| Error::Unclassified("No response from endpoint".into()))?;

        if !response.status().is_success() {
            let status = response.status();
            let bytes = response.bytes().await?;
            return Err(Error::FailedRequest(
                endpoint,
                "Unable to retrieve data from endpoint".to_owned(),
                status,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }

        response
            .bytes()
            .await
            .map_err(Error::Reqwest)
            .map(|b| b.to_vec())
    }
}
