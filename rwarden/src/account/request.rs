use crate::{account::Account, cache::Cache, util::ResponseExt, Error, Request, Session};
use reqwest::Method;
use rwarden_crypto::{CipherString, KdfType, MasterPasswordHash};
use serde_json::json;

#[derive(Debug)]
pub struct Get<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for Get<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> Get<'session, TCache> {
    pub async fn execute(&mut self) -> crate::Result<Account, TCache::Error> {
        let value = self
            .session
            .request(
                Method::GET,
                format!("{}/accounts/profile", self.session.urls().base),
            )
            .await?
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_account(&value)
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct Modify<'session, TCache> {
    session: &'session mut Session<TCache>,
}

impl<'session, TCache> Request<'session, TCache> for Modify<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self { session }
    }
}

impl<'session, TCache: Cache> Modify<'session, TCache> {
    pub fn profile(self) -> ModifyProfile<'session, TCache> {
        ModifyProfile::new(self.session)
    }

    pub fn email(self) -> DefaultModifyEmail<'session, TCache> {
        ModifyEmail::new(self.session)
    }

    pub fn password(self) -> DefaultModifyPassword<'session, TCache> {
        ModifyPassword::new(self.session)
    }

    pub fn kdf(self) -> DefaultModifyKdf<'session, TCache> {
        ModifyKdf::new(self.session)
    }
}

#[derive(Debug)]
pub struct ModifyProfile<'session, TCache> {
    session: &'session mut Session<TCache>,
    name: Option<String>,
    master_password_hint: Option<String>,
    culture: Option<String>,
}

impl<'session, TCache> Request<'session, TCache> for ModifyProfile<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            name: None,
            master_password_hint: None,
            culture: None,
        }
    }
}

impl<'session, TCache> ModifyProfile<'session, TCache> {
    pub fn name<S: Into<String>>(mut self, value: S) -> Self {
        self.name = Some(value.into());
        self
    }

    pub fn master_password_hint<S: Into<String>>(mut self, value: S) -> Self {
        self.master_password_hint = Some(value.into());
        self
    }

    pub fn culture<S: Into<String>>(mut self, value: S) -> Self {
        self.culture = Some(value.into());
        self
    }
}

impl<'session, TCache: Cache> ModifyProfile<'session, TCache> {
    pub async fn execute(&mut self) -> crate::Result<Account, TCache::Error> {
        let value = self
            .session
            .request(
                Method::PUT,
                format!("{}/accounts/profile", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "Name": self.name,
                "MasterPasswordHint": self.master_password_hint,
                "Culture": self.culture,
            }))
            .send()
            .await?
            .parse()
            .await?;
        self.session
            .cache_mut()
            .save_account(&value)
            .await
            .map_err(Error::Cache)?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct ModifyEmail<
    'session,
    TCache,
    PNewEmail,
    PMasterPasswordHash,
    PNewMasterPasswordHash,
    PToken,
    PKey,
> {
    session: &'session mut Session<TCache>,
    new_email: PNewEmail,
    master_password_hash: PMasterPasswordHash,
    new_master_password_hash: PNewMasterPasswordHash,
    token: PToken,
    key: PKey,
}

pub type DefaultModifyEmail<'session, TCache> = ModifyEmail<'session, TCache, (), (), (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyEmail<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            new_email: (),
            master_password_hash: (),
            new_master_password_hash: (),
            token: (),
            key: (),
        }
    }
}

impl<'session, TCache, PNewEmail, PMasterPasswordHash, PNewMasterPasswordHash, PToken, PKey>
    ModifyEmail<
        'session,
        TCache,
        PNewEmail,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PToken,
        PKey,
    >
{
    pub fn new_email<S: Into<String>>(
        self,
        value: S,
    ) -> ModifyEmail<
        'session,
        TCache,
        String,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PToken,
        PKey,
    > {
        ModifyEmail {
            session: self.session,
            new_email: value.into(),
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            token: self.token,
            key: self.key,
        }
    }

    pub fn master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyEmail<
        'session,
        TCache,
        PNewEmail,
        MasterPasswordHash,
        PNewMasterPasswordHash,
        PToken,
        PKey,
    > {
        ModifyEmail {
            session: self.session,
            new_email: self.new_email,
            master_password_hash: value,
            new_master_password_hash: self.new_master_password_hash,
            token: self.token,
            key: self.key,
        }
    }

    pub fn new_master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyEmail<
        'session,
        TCache,
        PNewEmail,
        PMasterPasswordHash,
        MasterPasswordHash,
        PToken,
        PKey,
    > {
        ModifyEmail {
            session: self.session,
            new_email: self.new_email,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: value,
            token: self.token,
            key: self.key,
        }
    }

    pub fn token<S: Into<String>>(
        self,
        value: S,
    ) -> ModifyEmail<
        'session,
        TCache,
        PNewEmail,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        String,
        PKey,
    > {
        ModifyEmail {
            session: self.session,
            new_email: self.new_email,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            token: value.into(),
            key: self.key,
        }
    }

    pub fn key(
        self,
        value: CipherString,
    ) -> ModifyEmail<
        'session,
        TCache,
        PNewEmail,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PToken,
        CipherString,
    > {
        ModifyEmail {
            session: self.session,
            new_email: self.new_email,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            token: self.token,
            key: value,
        }
    }
}

impl<'session, TCache: Cache>
    ModifyEmail<
        'session,
        TCache,
        String,
        MasterPasswordHash,
        MasterPasswordHash,
        String,
        CipherString,
    >
{
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::PUT,
                format!("{}/accounts/email", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "NewEmail": self.new_email,
                "MasterPasswordHash": self.master_password_hash,
                "NewMasterPasswordHash": self.new_master_password_hash,
                "Token": self.token,
                "Key": self.key,
            }))
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ModifyPassword<'session, TCache, PMasterPasswordHash, PNewMasterPasswordHash, PKey> {
    session: &'session mut Session<TCache>,
    master_password_hash: PMasterPasswordHash,
    new_master_password_hash: PNewMasterPasswordHash,
    key: PKey,
}

pub type DefaultModifyPassword<'session, TCache> = ModifyPassword<'session, TCache, (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyPassword<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            master_password_hash: (),
            new_master_password_hash: (),
            key: (),
        }
    }
}

impl<'session, TCache, PMasterPasswordHash, PNewMasterPasswordHash, PKey>
    ModifyPassword<'session, TCache, PMasterPasswordHash, PNewMasterPasswordHash, PKey>
{
    pub fn master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyPassword<'session, TCache, MasterPasswordHash, PNewMasterPasswordHash, PKey> {
        ModifyPassword {
            session: self.session,
            master_password_hash: value,
            new_master_password_hash: self.new_master_password_hash,
            key: self.key,
        }
    }

    pub fn new_master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyPassword<'session, TCache, PMasterPasswordHash, MasterPasswordHash, PKey> {
        ModifyPassword {
            session: self.session,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: value,
            key: self.key,
        }
    }

    pub fn key(
        self,
        value: CipherString,
    ) -> ModifyPassword<'session, TCache, PMasterPasswordHash, PNewMasterPasswordHash, CipherString>
    {
        ModifyPassword {
            session: self.session,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            key: value,
        }
    }
}

impl<'session, TCache: Cache>
    ModifyPassword<'session, TCache, MasterPasswordHash, MasterPasswordHash, CipherString>
{
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::POST,
                format!("{}/accounts/password", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "MasterPasswordHash": self.master_password_hash,
                "NewMasterPasswordHash": self.new_master_password_hash,
                "Key": self.key,
            }))
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ModifyKdf<
    'session,
    TCache,
    PKdfType,
    PKdfIterations,
    PMasterPasswordHash,
    PNewMasterPasswordHash,
    PKey,
> {
    session: &'session mut Session<TCache>,
    kdf_type: PKdfType,
    kdf_iterations: PKdfIterations,
    master_password_hash: PMasterPasswordHash,
    new_master_password_hash: PNewMasterPasswordHash,
    key: PKey,
}

pub type DefaultModifyKdf<'session, TCache> = ModifyKdf<'session, TCache, (), (), (), (), ()>;

impl<'session, TCache> Request<'session, TCache> for DefaultModifyKdf<'session, TCache> {
    fn new(session: &'session mut Session<TCache>) -> Self {
        Self {
            session,
            kdf_type: (),
            kdf_iterations: (),
            master_password_hash: (),
            new_master_password_hash: (),
            key: (),
        }
    }
}

impl<
        'session,
        TCache,
        PKdfType,
        PKdfIterations,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PKey,
    >
    ModifyKdf<
        'session,
        TCache,
        PKdfType,
        PKdfIterations,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PKey,
    >
{
    pub fn kdf_type(
        self,
        value: KdfType,
    ) -> ModifyKdf<
        'session,
        TCache,
        KdfType,
        PKdfIterations,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        PKey,
    > {
        ModifyKdf {
            session: self.session,
            kdf_type: value,
            kdf_iterations: self.kdf_iterations,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            key: self.key,
        }
    }

    pub fn kdf_iterations(
        self,
        value: u32,
    ) -> ModifyKdf<'session, TCache, PKdfType, u32, PMasterPasswordHash, PNewMasterPasswordHash, PKey>
    {
        ModifyKdf {
            session: self.session,
            kdf_type: self.kdf_type,
            kdf_iterations: value,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            key: self.key,
        }
    }

    pub fn master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyKdf<
        'session,
        TCache,
        PKdfType,
        PKdfIterations,
        MasterPasswordHash,
        PNewMasterPasswordHash,
        PKey,
    > {
        ModifyKdf {
            session: self.session,
            kdf_type: self.kdf_type,
            kdf_iterations: self.kdf_iterations,
            master_password_hash: value,
            new_master_password_hash: self.new_master_password_hash,
            key: self.key,
        }
    }

    pub fn new_master_password_hash(
        self,
        value: MasterPasswordHash,
    ) -> ModifyKdf<
        'session,
        TCache,
        PKdfType,
        PKdfIterations,
        PMasterPasswordHash,
        MasterPasswordHash,
        PKey,
    > {
        ModifyKdf {
            session: self.session,
            kdf_type: self.kdf_type,
            kdf_iterations: self.kdf_iterations,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: value,
            key: self.key,
        }
    }

    pub fn key(
        self,
        value: CipherString,
    ) -> ModifyKdf<
        'session,
        TCache,
        PKdfType,
        PKdfIterations,
        PMasterPasswordHash,
        PNewMasterPasswordHash,
        CipherString,
    > {
        ModifyKdf {
            session: self.session,
            kdf_type: self.kdf_type,
            kdf_iterations: self.kdf_iterations,
            master_password_hash: self.master_password_hash,
            new_master_password_hash: self.new_master_password_hash,
            key: value,
        }
    }
}

impl<'session, TCache: Cache>
    ModifyKdf<'session, TCache, KdfType, u32, MasterPasswordHash, MasterPasswordHash, CipherString>
{
    pub async fn execute(&mut self) -> crate::Result<(), TCache::Error> {
        self.session
            .request(
                Method::POST,
                format!("{}/accounts/kdf", self.session.urls().base),
            )
            .await?
            .json(&json!({
                "Kdf": self.kdf_type,
                "KdfIterations": self.kdf_iterations,
                "MasterPasswordHash": self.master_password_hash,
                "NewMasterPasswordHash": self.new_master_password_hash,
                "Key": self.key,
            }))
            .send()
            .await?
            .parse_empty()
            .await?;
        Ok(())
    }
}
