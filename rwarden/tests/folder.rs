use futures::stream::TryStreamExt;
use rwarden::{crypto::CipherString, folder::Folder};

mod common;

#[tokio::test]
async fn folder_create() {
    let mut session = common::login().await.unwrap();
    common::create_default_folder(&mut session).await.unwrap();
}

#[tokio::test]
async fn folder_get() {
    let mut session = common::login().await.unwrap();
    let created_folder = common::create_default_folder(&mut session).await.unwrap();
    let retrieved_folder = session
        .get::<Folder>()
        .id(created_folder.id)
        .execute()
        .await
        .unwrap();
    assert_eq!(created_folder, retrieved_folder);
}

#[tokio::test]
async fn folder_get_all() {
    let mut session = common::login().await.unwrap();
    session
        .get_all::<Folder>()
        .execute()
        .try_concat()
        .await
        .unwrap();
}

#[tokio::test]
async fn folder_delete() {
    let mut session = common::login().await.unwrap();
    let created_folder = common::create_default_folder(&mut session).await.unwrap();
    session
        .delete::<Folder>()
        .id(created_folder.id)
        .execute()
        .await
        .unwrap();
    let folder_result = session
        .get::<Folder>()
        .id(created_folder.id)
        .execute()
        .await;
    // TODO: Check that the correct error is returned
    assert!(folder_result.is_err());
}

#[tokio::test]
async fn folder_modify() {
    let mut session = common::login().await.unwrap();
    let folder = common::create_default_folder(&mut session).await.unwrap();
    let name = CipherString::encrypt_with_keys("foo2", session.keys());
    let folder = session
        .modify::<Folder>()
        .id(folder.id)
        .name(name.clone())
        .execute()
        .await
        .unwrap();
    assert_eq!(folder.name, name);
}
