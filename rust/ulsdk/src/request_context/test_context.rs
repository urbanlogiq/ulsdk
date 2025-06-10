// Copyright (c), CommunityLogiq Software

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Error;
use crate::request_context::{ApiKeyContext, File, HeaderMap, ParamMap, RequestContext};
use crate::{Environment, Region};

pub(crate) struct TestContext {
    context: ApiKeyContext,
    response: Vec<u8>,
}

impl TestContext {
    pub(crate) fn new(context: ApiKeyContext) -> Self {
        Self {
            context,
            response: Vec::new(),
        }
    }

    pub(crate) fn set_response<T>(&mut self, r: T)
    where
        T: Into<Vec<u8>>,
    {
        self.response = r.into();
    }
}

#[async_trait]
impl RequestContext for TestContext {
    fn region(&self) -> Region {
        self.context.region()
    }

    fn environment(&self) -> Environment {
        self.context.environment()
    }

    async fn get(
        &self,
        _path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let echo_path = "/v1/echo/";

        self.context.get(echo_path, params, headers).await?;
        Ok(self.response.clone())
    }

    async fn put(
        &self,
        _path: &str,
        _body: Bytes,
        mimetype: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let echo_path = "/v1/echo/";

        let response = self.response.clone();
        let response_bytes = Bytes::from(response.clone());
        let r = self
            .context
            .put(echo_path, response_bytes, mimetype, params, headers)
            .await?;

        if r != response {
            return Err(Error::Unclassified(
                "Test failure, expected response to match request".into(),
            ));
        }

        Ok(response)
    }

    async fn post(
        &self,
        _path: &str,
        _body: Bytes,
        mimetype: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let echo_path = "/v1/echo/";

        let response = self.response.clone();
        let response_bytes = Bytes::from(response.clone());
        let r = self
            .context
            .post(echo_path, response_bytes, mimetype, params, headers)
            .await?;

        if r != response {
            return Err(Error::Unclassified(
                "Test failure, expected response to match request".into(),
            ));
        }

        Ok(response)
    }

    async fn upload(&self, _path: &str, files: Vec<File>) -> Result<Vec<u8>, Error> {
        let echo_path = "/v1/echo/";

        self.context.upload(echo_path, files).await?;

        Ok(self.response.clone())
    }

    async fn delete(
        &self,
        _path: &str,
        params: Option<ParamMap>,
        headers: Option<HeaderMap>,
    ) -> Result<Vec<u8>, Error> {
        let echo_path = "/v1/echo/";

        self.context.delete(echo_path, params, headers).await?;
        Ok(self.response.clone())
    }
}
