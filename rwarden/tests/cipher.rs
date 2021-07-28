mod common;

use futures::stream::TryStreamExt;
use rwarden::cipher::{Cipher, CipherDetails, Field, FieldType, RequestModel};
use rwarden::crypto::{CipherString, KdfType, MasterPasswordHash, SourceKey};

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
    let mut session = common::login().await.unwrap();
    common::create_default_cipher(&mut session).await.unwrap();
}

#[tokio::test]
async fn cipher_get() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    let retrieved_cipher = session
        .get::<Cipher>()
        .id(created_cipher.id)
        .execute()
        .await
        .unwrap();
    assert_eq_cipher_except_revision_date(&created_cipher, &retrieved_cipher);
}

#[tokio::test]
async fn cipher_soft_delete() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    session
        .delete::<Cipher>()
        .id(created_cipher.id)
        .soft_delete(true)
        .execute()
        .await
        .unwrap();
    let cipher = session
        .get::<Cipher>()
        .id(created_cipher.id)
        .execute()
        .await
        .unwrap();
    assert!(cipher.deleted_date.is_some());
}

#[tokio::test]
async fn cipher_hard_delete() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    session
        .delete::<Cipher>()
        .id(created_cipher.id)
        .soft_delete(false)
        .execute()
        .await
        .unwrap();
    let cipher_result = session
        .get::<Cipher>()
        .id(created_cipher.id)
        .execute()
        .await;
    // TODO: Check that the correct error is returned
    assert!(cipher_result.is_err());
}

#[tokio::test]
async fn cipher_bulk_soft_delete() {
    let mut session = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut session).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut session).await.unwrap();
    session
        .bulk_delete::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .soft_delete(true)
        .execute()
        .await
        .unwrap();
    let cipher1 = session
        .get::<Cipher>()
        .id(cipher1.id)
        .execute()
        .await
        .unwrap();
    let cipher2 = session
        .get::<Cipher>()
        .id(cipher2.id)
        .execute()
        .await
        .unwrap();
    assert!(cipher1.deleted_date.is_some());
    assert!(cipher2.deleted_date.is_some());
}

#[tokio::test]
async fn cipher_bulk_hard_delete() {
    let mut session = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut session).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut session).await.unwrap();
    session
        .bulk_delete::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .soft_delete(false)
        .execute()
        .await
        .unwrap();
    let cipher1_result = session.get::<Cipher>().id(cipher1.id).execute().await;
    let cipher2_result = session.get::<Cipher>().id(cipher2.id).execute().await;
    // TODO: Check that the correct error is returned
    assert!(cipher1_result.is_err());
    assert!(cipher2_result.is_err());
}

#[tokio::test]
async fn cipher_modify_complete() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    let folder = common::create_default_folder(&mut session).await.unwrap();
    let name = CipherString::encrypt_with_keys("foo2", session.keys());
    let ty = created_cipher.ty;
    let notes = CipherString::encrypt_with_keys("notes...", session.keys());
    let fields = vec![
        Field {
            ty: FieldType::Text,
            name: Some(CipherString::encrypt_with_keys("field1", session.keys())),
            value: Some(CipherString::encrypt_with_keys("value1", session.keys())),
        },
        Field {
            ty: FieldType::Hidden,
            name: Some(CipherString::encrypt_with_keys("field2", session.keys())),
            value: Some(CipherString::encrypt_with_keys("value2", session.keys())),
        },
        Field {
            ty: FieldType::Boolean,
            name: Some(CipherString::encrypt_with_keys("field3", session.keys())),
            value: Some(CipherString::encrypt_with_keys("true", session.keys())),
        },
    ];
    let cipher = session
        .modify::<Cipher>()
        .complete()
        .id(created_cipher.id)
        .request_model(
            RequestModel::new(name.clone(), ty.clone())
                .with_folder_id(folder.id)
                .with_notes(notes.clone())
                .with_fields(fields.clone())
                .with_favorite(true),
        )
        .execute()
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
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    let folder = common::create_default_folder(&mut session).await.unwrap();
    session
        .modify::<Cipher>()
        .partial()
        .id(created_cipher.id)
        .folder_id(folder.id)
        .favorite(true)
        .execute()
        .await
        .unwrap();
    let cipher = session
        .get::<Cipher>()
        .id(created_cipher.id)
        .execute()
        .await
        .unwrap();
    assert_eq!(cipher.folder_id, Some(folder.id));
    assert_eq!(cipher.favorite, true);
}

// TODO: Test modify collections

#[tokio::test]
async fn cipher_restore() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    session
        .delete::<Cipher>()
        .id(created_cipher.id)
        .soft_delete(true)
        .execute()
        .await
        .unwrap();
    let restored_cipher = session
        .restore::<Cipher>()
        .id(created_cipher.id)
        .execute()
        .await
        .unwrap();
    assert!(restored_cipher.deleted_date.is_none());
}

#[tokio::test]
async fn cipher_bulk_restore() {
    let mut session = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut session).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut session).await.unwrap();
    session
        .bulk_delete::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .soft_delete(true)
        .execute()
        .await
        .unwrap();
    let ciphers = session
        .bulk_restore::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .execute()
        .try_concat()
        .await
        .unwrap();
    assert_eq!(ciphers.len(), 2);
    assert!(ciphers.into_iter().all(|v| v.deleted_date.is_none()));
}

// TODO: Test share and bulk share

#[tokio::test]
async fn cipher_bulk_move() {
    let mut session = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut session).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut session).await.unwrap();

    // Create folder and move ciphers into it
    let folder = common::create_default_folder(&mut session).await.unwrap();
    session
        .bulk_move::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .folder_id(Some(folder.id))
        .execute()
        .await
        .unwrap();
    let cipher1 = session
        .get::<Cipher>()
        .id(cipher1.id)
        .execute()
        .await
        .unwrap();
    let cipher2 = session
        .get::<Cipher>()
        .id(cipher2.id)
        .execute()
        .await
        .unwrap();
    assert_eq!(cipher1.folder_id, Some(folder.id));
    assert_eq!(cipher2.folder_id, Some(folder.id));

    // Move ciphers back into no folder
    session
        .bulk_move::<Cipher>()
        .ids(vec![cipher1.id, cipher2.id])
        .folder_id(None)
        .execute()
        .await
        .unwrap();
    let cipher1 = session
        .get::<Cipher>()
        .id(cipher1.id)
        .execute()
        .await
        .unwrap();
    let cipher2 = session
        .get::<Cipher>()
        .id(cipher2.id)
        .execute()
        .await
        .unwrap();
    assert_eq!(cipher1.folder_id, None);
    assert_eq!(cipher2.folder_id, None);
}

#[tokio::test]
#[ignore] // This test interferes with some other tests
async fn cipher_purge() {
    let mut session = common::login().await.unwrap();
    let cipher1 = common::create_default_cipher(&mut session).await.unwrap();
    let cipher2 = common::create_default_cipher(&mut session).await.unwrap();
    // TODO: KDF type and iterations should not be hardcoded here
    let source_key = SourceKey::new(
        common::EMAIL,
        common::PASSWORD,
        KdfType::Pbkdf2Sha256,
        100_000,
    );
    let master_password_hash =
        MasterPasswordHash::new(&source_key, common::PASSWORD, KdfType::Pbkdf2Sha256);
    session
        .purge::<Cipher>()
        .master_password_hash(master_password_hash)
        .execute()
        .await
        .unwrap();
    let cipher1_result = session.get::<Cipher>().id(cipher1.id).execute().await;
    let cipher2_result = session.get::<Cipher>().id(cipher2.id).execute().await;
    // TODO: Check that the correct error is returned
    assert!(cipher1_result.is_err());
    assert!(cipher2_result.is_err());
}

#[tokio::test]
async fn cipher_get_details() {
    let mut session = common::login().await.unwrap();
    let created_cipher = common::create_default_cipher(&mut session).await.unwrap();
    let retrieved_cipher = session
        .get::<CipherDetails>()
        .id(created_cipher.id)
        .execute()
        .await
        .unwrap();
    assert_eq_cipher_except_revision_date(&created_cipher, &retrieved_cipher.inner)
}

#[tokio::test]
async fn cipher_get_all_details() {
    let mut session = common::login().await.unwrap();
    session
        .get_all::<CipherDetails>()
        .execute()
        .try_concat()
        .await
        .unwrap();
}
