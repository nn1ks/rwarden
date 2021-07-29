use crate::{response, RequestResponseError};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Deserializer};
use std::convert::TryInto;
use std::time::{Duration, SystemTime};

pub fn deserialize_optional<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let value: Option<T> = Deserialize::deserialize(deserializer)?;
    Ok(value.unwrap_or_default())
}

pub fn get_token_expiry_time(expires_in: Option<i64>) -> SystemTime {
    SystemTime::now()
        + expires_in
            .map(|v| v.try_into().map(Duration::from_secs).unwrap_or_default())
            .unwrap_or_default()
}

#[async_trait]
pub trait ResponseExt {
    async fn parse<T: DeserializeOwned>(self) -> Result<T, RequestResponseError>;
    async fn parse_empty(self) -> Result<(), RequestResponseError>;
}

#[async_trait]
impl ResponseExt for reqwest::Response {
    async fn parse<T: DeserializeOwned>(self) -> Result<T, RequestResponseError> {
        if self.status().is_success() {
            Ok(self.json().await?)
        } else {
            let e = self.json::<response::Error>().await?;
            return Err(e.into());
        }
    }

    async fn parse_empty(self) -> Result<(), RequestResponseError> {
        if self.status().is_success() {
            Ok(())
        } else {
            let e = self.json::<response::Error>().await?;
            return Err(e.into());
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    pub continuation_token: Option<String>,
}

macro_rules! request_stream {
    ($build_request:expr, $response:ident => $save_cache:expr) => {
        Box::pin(async_stream::try_stream! {
            let mut continuation_token = None;
            let mut is_first_iteration = true;
            while continuation_token.is_some() || is_first_iteration {
                let mut request = $build_request;
                if let Some(v) = &continuation_token {
                    request = request.query(&[("continuationToken", v)])
                }
                let $response = request
                    .send()
                    .await?
                    .parse::<crate::util::ListResponse<_>>()
                    .await?;
                $save_cache;
                continuation_token = $response.continuation_token;
                is_first_iteration = false;
                yield $response.data;
            }
        })
    };
    ($build_request:expr) => {
        request_stream! { $build_request, response => {} }
    };
}
