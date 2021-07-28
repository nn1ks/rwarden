mod common;

use rwarden::sync::Sync;

#[tokio::test]
async fn get() {
    let mut session = common::login().await.unwrap();
    session.get::<Sync>().execute().await.unwrap();
}
