mod common;

use futures::stream::TryStreamExt;
use rwarden::cipher::{self, Cipher, CipherDetails, Field, FieldType, RequestModel};
use rwarden::crypto::{KdfType, MasterPasswordHash, SourceKey, SymmetricEncryptedString};

fn assert_eq_cipher_except_revision_date(a: &Cipher, b: &Cipher) {
    let Cipher {
        id,
        folder_id,
        organization_id,
        name,
        ty,
        notes,
        fields,
        attachments,
        organization_use_totp,
        password_history,
        revision_date: _,
        deleted_date,
        favorite,
        edit,
        view_password,
    } = a;
    assert_eq!(id, &b.id);
    assert_eq!(folder_id, &b.folder_id);
    assert_eq!(organization_id, &b.organization_id);
    assert_eq!(name, &b.name);
    assert_eq!(ty, &b.ty);
    assert_eq!(notes, &b.notes);
    assert_eq!(fields, &b.fields);
    assert_eq!(attachments, &b.attachments);
    assert_eq!(organization_use_totp, &b.organization_use_totp);
    assert_eq!(password_history, &b.password_history);
    assert_eq!(deleted_date, &b.deleted_date);
    assert_eq!(favorite, &b.favorite);
    assert_eq!(edit, &b.edit);
    assert_eq!(view_password, &b.view_password);
}

#[tokio::test]
async fn cipher_create() {
    let mut client = common::login().await.unwrap();
    common::create_default_cipher(&mut client).await.unwrap();
}

#[tokio::test]
async fn cipher_get() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    let retrieved_cipher = client
        .send(&cipher::Get {
            id: created_cipher.id,
        })
        .await
        .unwrap();
    assert_eq_cipher_except_revision_date(&created_cipher, &retrieved_cipher);
}

#[tokio::test]
async fn cipher_soft_delete() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(&cipher::Delete {
            id: created_cipher.id,
            soft_delete: true,
        })
        .await
        .unwrap();
    let cipher = client
        .send(&cipher::Get {
            id: created_cipher.id,
        })
        .await
        .unwrap();
    assert!(cipher.deleted_date.is_some());
}

#[tokio::test]
async fn cipher_hard_delete() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(&cipher::Delete {
            id: created_cipher.id,
            soft_delete: false,
        })
        .await
        .unwrap();
    let cipher_result = client
        .send(&cipher::Get {
            id: created_cipher.id,
        })
        .await;
    // TODO: Check that the correct error is returned
    assert!(cipher_result.is_err());
}

#[tokio::test]
async fn cipher_bulk_soft_delete() {
    let mut client = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut client).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(
            &cipher::BulkDelete::builder()
                .ids(vec![cipher1.id, cipher2.id])
                .soft_delete(true)
                .build(),
        )
        .await
        .unwrap();
    let cipher1 = client.send(&cipher::Get { id: cipher1.id }).await.unwrap();
    let cipher2 = client.send(&cipher::Get { id: cipher2.id }).await.unwrap();
    assert!(cipher1.deleted_date.is_some());
    assert!(cipher2.deleted_date.is_some());
}

#[tokio::test]
async fn cipher_bulk_hard_delete() {
    let mut client = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut client).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(
            &cipher::BulkDelete::builder()
                .ids(vec![cipher1.id, cipher2.id])
                .soft_delete(false)
                .build(),
        )
        .await
        .unwrap();
    let cipher1_result = client.send(&cipher::Get { id: cipher1.id }).await;
    let cipher2_result = client.send(&cipher::Get { id: cipher2.id }).await;
    // TODO: Check that the correct error is returned
    assert!(cipher1_result.is_err());
    assert!(cipher2_result.is_err());
}

#[tokio::test]
async fn cipher_modify_complete() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    let folder = common::create_default_folder(&mut client).await.unwrap();
    let name = SymmetricEncryptedString::encrypt("foo2", client.symmetric_key());
    let ty = created_cipher.ty;
    let notes = SymmetricEncryptedString::encrypt("notes...", client.symmetric_key());
    let create_field = |ty, name, value| Field {
        ty,
        name: Some(SymmetricEncryptedString::encrypt(
            name,
            client.symmetric_key(),
        )),
        value: Some(SymmetricEncryptedString::encrypt(
            value,
            client.symmetric_key(),
        )),
    };
    let fields = vec![
        create_field(FieldType::Text, "field1", "value1"),
        create_field(FieldType::Hidden, "field2", "value2"),
        create_field(FieldType::Boolean, "field3", "true"),
    ];
    let cipher = client
        .send(&cipher::Modify {
            id: created_cipher.id,
            request_model: RequestModel::new(name.clone(), ty.clone())
                .with_folder_id(folder.id)
                .with_notes(notes.clone())
                .with_fields(fields.clone())
                .with_favorite(true),
        })
        .await
        .unwrap();
    assert_eq!(cipher.name, name);
    assert_eq!(cipher.ty, ty);
    assert_eq!(cipher.notes, Some(notes));
    assert_eq!(cipher.fields, fields);
    assert_eq!(cipher.folder_id, Some(folder.id));
    assert_eq!(cipher.favorite, true);
}

#[tokio::test]
#[cfg_attr(feature = "disable_vaultwarden_incompatible_tests", ignore)]
async fn cipher_modify_partial() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    let folder = common::create_default_folder(&mut client).await.unwrap();
    client
        .send(
            &cipher::ModifyPartial::builder()
                .id(created_cipher.id)
                .folder_id(folder.id)
                .favorite(true)
                .build(),
        )
        .await
        .unwrap();
    let cipher = client
        .send(&cipher::Get {
            id: created_cipher.id,
        })
        .await
        .unwrap();
    assert_eq!(cipher.folder_id, Some(folder.id));
    assert_eq!(cipher.favorite, true);
}

// TODO: Test modify collections

#[tokio::test]
async fn cipher_restore() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(&cipher::Delete {
            id: created_cipher.id,
            soft_delete: true,
        })
        .await
        .unwrap();
    let restored_cipher = client
        .send(&cipher::Restore {
            id: created_cipher.id,
        })
        .await
        .unwrap();
    assert!(restored_cipher.deleted_date.is_none());
}

#[tokio::test]
async fn cipher_bulk_restore() {
    let mut client = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut client).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut client).await.unwrap();
    client
        .send(
            &cipher::BulkDelete::builder()
                .ids(vec![cipher1.id, cipher2.id])
                .soft_delete(true)
                .build(),
        )
        .await
        .unwrap();
    let ciphers = client
        .send(&cipher::BulkRestore {
            ids: vec![cipher1.id, cipher2.id],
        })
        .try_concat()
        .await
        .unwrap();
    assert_eq!(ciphers.len(), 2);
    assert!(ciphers.into_iter().all(|v| v.deleted_date.is_none()));
}

// TODO: Test share and bulk share

#[tokio::test]
async fn cipher_bulk_move() {
    let mut client = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut client).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut client).await.unwrap();

    // Create folder and move ciphers into it
    let folder = common::create_default_folder(&mut client).await.unwrap();
    client
        .send(&cipher::BulkMove {
            ids: vec![cipher1.id, cipher2.id],
            folder_id: Some(folder.id),
        })
        .await
        .unwrap();
    let cipher1 = client.send(&cipher::Get { id: cipher1.id }).await.unwrap();
    let cipher2 = client.send(&cipher::Get { id: cipher2.id }).await.unwrap();
    assert_eq!(cipher1.folder_id, Some(folder.id));
    assert_eq!(cipher2.folder_id, Some(folder.id));

    // Move ciphers back into no folder
    client
        .send(&cipher::BulkMove {
            ids: vec![cipher1.id, cipher2.id],
            folder_id: None,
        })
        .await
        .unwrap();
    let cipher1 = client.send(&cipher::Get { id: cipher1.id }).await.unwrap();
    let cipher2 = client.send(&cipher::Get { id: cipher2.id }).await.unwrap();
    assert_eq!(cipher1.folder_id, None);
    assert_eq!(cipher2.folder_id, None);
}

#[tokio::test]
#[ignore] // This test interferes with some other tests
async fn cipher_purge() {
    let mut client = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut client).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut client).await.unwrap();
    // TODO: KDF type and iterations should not be hardcoded here
    let source_key = SourceKey::new(
        common::EMAIL,
        common::PASSWORD,
        KdfType::Pbkdf2Sha256,
        100_000,
    );
    let master_password_hash =
        MasterPasswordHash::new(&source_key, common::PASSWORD, KdfType::Pbkdf2Sha256);
    client
        .send(
            &cipher::Purge::builder()
                .master_password_hash(master_password_hash)
                .build(),
        )
        .await
        .unwrap();
    let cipher1_result = client.send(&cipher::Get { id: cipher1.id }).await;
    let cipher2_result = client.send(&cipher::Get { id: cipher2.id }).await;
    // TODO: Check that the correct error is returned
    assert!(cipher1_result.is_err());
    assert!(cipher2_result.is_err());
}

#[tokio::test]
async fn cipher_get_details() {
    let mut client = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut client).await.unwrap();
    let retrieved_cipher = client
        .send(&cipher::GetDetails {
            id: created_cipher.id,
        })
        .await
        .unwrap();
    assert_eq_cipher_except_revision_date(&created_cipher, &retrieved_cipher.inner)
}

#[tokio::test]
async fn cipher_get_all_details() {
    let mut client = common::login().await.unwrap();
    let _ciphers: Vec<CipherDetails> = client
        .send(&cipher::GetAllDetails)
        .try_concat()
        .await
        .unwrap();
}
