#![allow(dead_code)] // https://github.com/rust-lang/rust/issues/46379

use rwarden::cache::{Cache, EmptyCache};
use rwarden::cipher::{self, Cipher};
use rwarden::folder::{self, Folder};
use rwarden::{
    crypto::SymmetricEncryptedString, AnonymousClient, Client, DeviceType, LoginData, LoginError,
    Urls,
};
use url::Url;

pub const BASE_URL: &str = env!("RWARDEN_BASE_URL");
pub const AUTH_URL: &str = env!("RWARDEN_AUTH_URL");
pub const EMAIL: &str = env!("RWARDEN_EMAIL");
pub const PASSWORD: &str = env!("RWARDEN_PASSWORD");

pub fn client() -> AnonymousClient {
    let urls = Urls {
        base: Url::parse(BASE_URL).unwrap(),
        auth: Url::parse(AUTH_URL).unwrap(),
    };
    AnonymousClient::new(urls)
}

pub fn login_data() -> LoginData {
    LoginData::new(EMAIL, PASSWORD, "desktop")
        .with_device_name("rwarden-test")
        .with_device_type(DeviceType::LinuxDesktop)
}

pub async fn login() -> Result<Client<EmptyCache>, LoginError> {
    let response = client().login(&login_data(), EmptyCache).await?;
    Ok(response.client)
}

pub async fn create_default_cipher<TCache: Cache + Send>(
    client: &mut Client<TCache>,
) -> rwarden::Result<Cipher, TCache::Error> {
    let name = SymmetricEncryptedString::encrypt("foo", client.symmetric_key());
    let request_model = cipher::RequestModel::new(
        name,
        cipher::Type::Login(cipher::Login {
            username: Some(SymmetricEncryptedString::encrypt(
                "bar",
                client.symmetric_key(),
            )),
            ..Default::default()
        }),
    );
    client
        .send(&cipher::Create {
            request_model,
            owner: cipher::Owner::User,
        })
        .await
}

pub async fn create_default_folder<TCache: Cache + Send>(
    client: &mut Client<TCache>,
) -> rwarden::Result<Folder, TCache::Error> {
    let folder_name = SymmetricEncryptedString::encrypt("foo", client.symmetric_key());
    client.send(&folder::Create { name: folder_name }).await
}
