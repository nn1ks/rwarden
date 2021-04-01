use crate::ResponseError;
use async_trait::async_trait;
use serde::de::DeserializeOwned;

macro_rules! path {
    ($($e:expr),*) => {
        vec![$(format!("{}", $e)),*]
    };
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
            let e = self.json::<ResponseError>().await?;
            return Err(e.into());
        }
    }
}
