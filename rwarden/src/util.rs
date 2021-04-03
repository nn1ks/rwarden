use crate::response;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Deserializer};

macro_rules! path {
    ($($e:expr),*) => {
        vec![$(format!("{}", $e)),*]
    };
}

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
    async fn parse<T: DeserializeOwned>(self) -> crate::Result<T>;
}

#[async_trait]
impl ResponseExt for reqwest::Response {
    async fn parse<T: DeserializeOwned>(self) -> crate::Result<T> {
        if self.status().is_success() {
            Ok(self.json().await?)
        } else {
            let e = self.json::<response::Error>().await?;
            return Err(e.into());
        }
    }
}
