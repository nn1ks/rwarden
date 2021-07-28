#![allow(dead_code)] // https://github.com/rust-lang/rust/issues/46379

use rwarden::cache::{Cache, EmptyCache};
use rwarden::cipher::{self, Cipher};
use rwarden::{crypto::CipherString, folder::Folder, Client, DeviceType, LoginData, Session, Urls};
use url::Url;

pub const BASE_URL: &str = env!("RWARDEN_BASE_URL");
pub const AUTH_URL: &str = env!("RWARDEN_AUTH_URL");
pub const EMAIL: &str = env!("RWARDEN_EMAIL");
pub const PASSWORD: &str = env!("RWARDEN_PASSWORD");

pub fn client() -> Client {
    let urls = Urls {
        base: Url::parse(BASE_URL).unwrap(),
        auth: Url::parse(AUTH_URL).unwrap(),
    };
    Client::new(urls)
}

pub fn login_data() -> LoginData {
    LoginData::new(EMAIL, PASSWORD, "desktop")
        .with_device_name("rwarden-test")
        .with_device_type(DeviceType::LinuxDesktop)
}

pub async fn login() -> rwarden::Result<Session<EmptyCache>, <EmptyCache as Cache>::Error> {
    client().login(&login_data(), EmptyCache).await
}

pub async fn create_default_cipher<TCache: Cache>(
    session: &mut Session<TCache>,
) -> rwarden::Result<Cipher, TCache::Error> {
    let name = CipherString::encrypt_with_keys("foo", session.keys());
    let request_model = cipher::RequestModel::new(
        name,
        cipher::Type::Login(cipher::Login {
            username: Some(CipherString::encrypt_with_keys("bar", session.keys())),
            ..Default::default()
        }),
    );
    session
        .create::<Cipher>()
        .request_model(request_model)
        .owner(cipher::Owner::User)
        .execute()
        .await
}

pub async fn create_default_folder<TCache: Cache>(
    session: &mut Session<TCache>,
) -> rwarden::Result<Folder, TCache::Error> {
    let folder_name = CipherString::encrypt_with_keys("foo", session.keys());
    session.create::<Folder>().name(folder_name).execute().await
}
