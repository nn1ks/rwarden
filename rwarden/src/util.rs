use crate::{response, RequestResponseError};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Deserializer};

pub fn deserialize_optional<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let value: Option<T> = Deserialize::deserialize(deserializer)?;
    Ok(value.unwrap_or_default())
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
