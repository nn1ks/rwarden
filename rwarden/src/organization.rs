//! Module for organization resources.

use crate::crypto::AsymmetricEncryptedBytes;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, DeserializeRepr, SerializeRepr)]
#[repr(u8)]
pub enum UserType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
    Custom = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, DeserializeRepr, SerializeRepr)]
#[repr(u8)]
pub enum UserStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Permissions {
    pub access_business_portal: bool,
    pub access_event_logs: bool,
    pub access_import_export: bool,
    pub access_reports: bool,
    pub manage_assigned_collections: bool,
    pub manage_all_collections: bool,
    pub manage_groups: bool,
    pub manage_policies: bool,
    pub manage_sso: bool,
    pub manage_users: bool,
    pub manage_reset_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccountOrganization {
    pub id: Uuid,
    pub name: String,
    pub use_policies: bool,
    pub use_sso: bool,
    pub use_groups: bool,
    pub use_directory: bool,
    pub use_events: bool,
    pub use_totp: bool,
    pub use_2fa: bool,
    pub use_api: bool,
    // pub use_reset_password: bool,
    pub use_business_portal: bool,
    pub users_get_premium: bool,
    pub self_host: bool,
    pub seats: Option<u32>,
    pub max_collections: Option<u32>,
    pub max_storage_gb: Option<u32>,
    pub key: AsymmetricEncryptedBytes,
    #[serde(rename = "Status")]
    pub user_status: UserStatus,
    #[serde(rename = "Type")]
    pub user_type: UserType,
    pub enabled: bool,
    pub sso_bound: bool,
    pub identifier: Option<String>,
    pub permissions: Option<Permissions>,
    pub reset_password_enrolled: bool,
    pub user_id: Option<String>,
    pub has_public_and_private_keys: bool,
    pub provider_id: Option<String>,
    pub provider_name: Option<String>,
}
