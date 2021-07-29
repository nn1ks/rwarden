mod common;

use rwarden::sync::{self, Sync};

#[tokio::test]
async fn sync_get() {
    let mut client = common::login().await.unwrap();
    let _snyc: Sync = client.send(&sync::Get).await.unwrap();
}
