mod common;

use rand::{distributions::Alphanumeric, Rng};
use rwarden::account::Account;

#[tokio::test]
async fn account_get() {
    let mut session = common::login().await.unwrap();
    session.get::<Account>().execute().await.unwrap();
}

#[tokio::test]
async fn account_modify_profile() {
    let mut session = common::login().await.unwrap();
    let random_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>();
    let name = format!("Name {}", random_string);
    let master_password_hint = format!("Password hint {}", random_string);
    let account = session
        .modify::<Account>()
        .profile()
        .name(name.clone())
        .master_password_hint(master_password_hint.clone())
        .culture("en-US")
        .execute()
        .await
        .unwrap();
    assert_eq!(account.name, Some(name));
    assert_eq!(account.master_password_hint, Some(master_password_hint));
}

// TODO: Test modify email
// TODO: Test modify password
// TODO: Test modify kdf
