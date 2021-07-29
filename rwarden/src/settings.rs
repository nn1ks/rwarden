//! Module for settings.

use serde::{Deserialize, Serialize};

pub use request::*;

mod request;

/// Multiple equivalent domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct EquivalentDomains(pub Vec<String>);

/// Domain settings.
// NOTE: Serialize is only needed for cache
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Domains {
    pub equivalent_domains: Vec<EquivalentDomains>,
    pub global_equivalent_domains: Vec<GlobalEquivalentDomains>,
}

impl Domains {
    /// Returns a list of all equivalent domains.
    pub fn all_equivalent_domains(&self) -> Vec<EquivalentDomains> {
        self.equivalent_domains
            .clone()
            .into_iter()
            .chain(
                self.global_equivalent_domains
                    .iter()
                    .filter(|v| !v.excluded)
                    .map(|v| v.domains.clone()),
            )
            .collect()
    }
}

/// Multiple globally equivalent domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GlobalEquivalentDomains {
    #[serde(rename = "Type")]
    pub ty: GlobalEquivalentDomainsType,
    pub domains: EquivalentDomains,
    pub excluded: bool,
}

// https://github.com/bitwarden/server/blob/v1.40.0/src/Core/Enums/GlobalEquivalentDomainsType.cs
/// The type of global equivalent domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct GlobalEquivalentDomainsType(pub u8);

impl GlobalEquivalentDomainsType {
    pub const GOOGLE: Self = Self(0);
    pub const APPLE: Self = Self(1);
    pub const AMERITRADE: Self = Self(2);
    pub const BOA: Self = Self(3);
    pub const SPRINT: Self = Self(4);
    pub const WELLS_FARGO: Self = Self(5);
    pub const MERRILL: Self = Self(6);
    pub const CITI: Self = Self(7);
    pub const CNET: Self = Self(8);
    pub const GAP: Self = Self(9);
    pub const MICROSOFT: Self = Self(10);
    pub const UNITED: Self = Self(11);
    pub const YAHOO: Self = Self(12);
    pub const ZONELABS: Self = Self(13);
    pub const PAY_PAL: Self = Self(14);
    pub const AVON: Self = Self(15);
    pub const DIAPERS: Self = Self(16);
    pub const CONTACTS: Self = Self(17);
    pub const AMAZON: Self = Self(18);
    pub const COX: Self = Self(19);
    pub const NORTON: Self = Self(20);
    pub const VERIZON: Self = Self(21);
    pub const BUY: Self = Self(22);
    pub const SIRIUS: Self = Self(23);
    pub const EA: Self = Self(24);
    pub const BASECAMP: Self = Self(25);
    pub const STEAM: Self = Self(26);
    pub const CHART: Self = Self(27);
    pub const GOTOMEETING: Self = Self(28);
    pub const GOGO: Self = Self(29);
    pub const ORACLE: Self = Self(30);
    pub const DISCOVER: Self = Self(31);
    pub const DCU: Self = Self(32);
    pub const HEALTHCARE: Self = Self(33);
    pub const PEPCO: Self = Self(34);
    pub const CENTURY21: Self = Self(35);
    pub const COMCAST: Self = Self(36);
    pub const CRICKET: Self = Self(37);
    pub const MTB: Self = Self(38);
    pub const DROPBOX: Self = Self(39);
    pub const SNAPFISH: Self = Self(40);
    pub const ALIBABA: Self = Self(41);
    pub const PLAYSTATION: Self = Self(42);
    pub const MERCADO: Self = Self(43);
    pub const ZENDESK: Self = Self(44);
    pub const AUTODESK: Self = Self(45);
    pub const RAIL_NATION: Self = Self(46);
    pub const WPCU: Self = Self(47);
    pub const MATHLETICS: Self = Self(48);
    pub const DISCOUNTBANK: Self = Self(49);
    pub const MI: Self = Self(50);
    pub const FACEBOOK: Self = Self(51);
    pub const POSTEPAY: Self = Self(52);
    pub const SKYSPORTS: Self = Self(53);
    pub const DISNEY: Self = Self(54);
    pub const POKEMON: Self = Self(55);
    pub const UV: Self = Self(56);
    pub const YAHAVO: Self = Self(57);
    pub const MDSOL: Self = Self(58);
    pub const SEARS: Self = Self(59);
    pub const XIAMI: Self = Self(60);
    pub const BELKIN: Self = Self(61);
    pub const TURBOTAX: Self = Self(62);
    pub const SHOPIFY: Self = Self(63);
    pub const EBAY: Self = Self(64);
    pub const TECHDATA: Self = Self(65);
    pub const SCHWAB: Self = Self(66);
    pub const MOZILLA: Self = Self(67); // deprecated
    pub const TESLA: Self = Self(68);
    pub const MORGAN_STANLEY: Self = Self(69);
    pub const TAX_ACT: Self = Self(70);
    pub const WIKIMEDIA: Self = Self(71);
    pub const AIRBNB: Self = Self(72);
    pub const EVENTBRITE: Self = Self(73);
    pub const STACK_EXCHANGE: Self = Self(74);
    pub const DOCUSIGN: Self = Self(75);
    pub const ENVATO: Self = Self(76);
    pub const X10_HOSTING: Self = Self(77);
    pub const CISCO: Self = Self(78);
    pub const CEDAR_FAIR: Self = Self(79);
    pub const UBIQUITI: Self = Self(80);
    pub const DISCORD: Self = Self(81);
    pub const NETCUP: Self = Self(82);
    pub const YANDEX: Self = Self(83);
    pub const SONY: Self = Self(84);
}
