use futures_util::TryStreamExt;
use rwarden::crypto::SymmetricEncryptedString;
use rwarden::folder::{self, Folder};

mod common;

#[tokio::test]
async fn folder_create() {
    let mut client = common::login().await.unwrap();
    common::create_default_folder(&mut client).await.unwrap();
}

#[tokio::test]
async fn folder_get() {
    let mut client = common::login().await.unwrap();
    let created_folder = common::create_default_folder(&mut client).await.unwrap();
    let retrieved_folder = client
        .send(&folder::Get {
            id: created_folder.id,
        })
        .await
        .unwrap();
    assert_eq!(created_folder, retrieved_folder);
}

#[tokio::test]
async fn folder_get_all() {
    let mut client = common::login().await.unwrap();
    let _folders: Vec<Folder> = client.send(&folder::GetAll).try_concat().await.unwrap();
}

#[tokio::test]
async fn folder_delete() {
    let mut client = common::login().await.unwrap();
    let created_folder = common::create_default_folder(&mut client).await.unwrap();
    client
        .send(&folder::Delete {
            id: created_folder.id,
        })
        .await
        .unwrap();
    let folder_result = client
        .send(&folder::Get {
            id: created_folder.id,
        })
        .await;
    // TODO: Check that the correct error is returned
    assert!(folder_result.is_err());
}

#[tokio::test]
async fn folder_modify() {
    let mut client = common::login().await.unwrap();
    let folder = common::create_default_folder(&mut client).await.unwrap();
    let name = SymmetricEncryptedString::encrypt("foo2", client.symmetric_key());
    let folder = client
        .send(&folder::Modify {
            id: folder.id,
            name: name.clone(),
        })
        .await
        .unwrap();
    assert_eq!(folder.name, name);
}
