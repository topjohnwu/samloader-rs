// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Classification of Samsung Odin firmware package entries.

/// Recognized Samsung Odin firmware component of a firmware archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OdinComponent {
    /// Bootloader package (`BL_` / `BOOTLOADER_`).
    Bl,
    /// Android OS / system package (`AP_` / `CODE_` / `PDA_`, or legacy `*_HOME.tar[.md5]`).
    Ap,
    /// Cellular modem / baseband package (`CP_` / `MODEM_` / `PHONE_`).
    Cp,
    /// Consumer Software Customization package (`CSC_`, wipes userdata).
    Csc,
    /// Non-wiping Home CSC package (`HOME_CSC_`, preserves userdata).
    HomeCsc,
    /// Userdata package (`USERDATA_`).
    Userdata,
}

impl OdinComponent {
    /// All recognized Samsung Odin firmware components in canonical order.
    pub const ALL: &'static [Self] = &[
        Self::Bl,
        Self::Ap,
        Self::Cp,
        Self::Csc,
        Self::HomeCsc,
        Self::Userdata,
    ];

    /// Classifies an archive entry file name by its Samsung prefix, if recognized.
    pub fn from_entry_name(name: &str) -> Option<Self> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let upper = base.to_ascii_uppercase();

        if upper.starts_with("HOME_CSC_") {
            Some(Self::HomeCsc)
        } else if upper.starts_with("CSC_") {
            Some(Self::Csc)
        } else if upper.starts_with("BL_") || upper.starts_with("BOOTLOADER_") {
            Some(Self::Bl)
        } else if upper.starts_with("AP_")
            || upper.starts_with("CODE_")
            || upper.starts_with("PDA_")
        {
            Some(Self::Ap)
        } else if upper.starts_with("CP_")
            || upper.starts_with("MODEM_")
            || upper.starts_with("PHONE_")
        {
            Some(Self::Cp)
        } else if upper.starts_with("USERDATA_") {
            Some(Self::Userdata)
        } else if upper.ends_with("_HOME.TAR.MD5") || upper.ends_with("_HOME.TAR") {
            Some(Self::Ap)
        } else {
            None
        }
    }

    /// Returns the canonical lowercase key for this component (e.g., `"bl"`, `"home_csc"`).
    pub const fn key(self) -> &'static str {
        match self {
            Self::Bl => "bl",
            Self::Ap => "ap",
            Self::Cp => "cp",
            Self::Csc => "csc",
            Self::HomeCsc => "home_csc",
            Self::Userdata => "userdata",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_odin_component_classification() {
        assert_eq!(
            OdinComponent::from_entry_name("BL_S931U1UES1AXB2.tar.md5"),
            Some(OdinComponent::Bl)
        );
        assert_eq!(
            OdinComponent::from_entry_name("BOOTLOADER_S931U1.tar.md5"),
            Some(OdinComponent::Bl)
        );
        assert_eq!(
            OdinComponent::from_entry_name("AP_S931U1UEU1AXB2.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(
            OdinComponent::from_entry_name("CODE_S931U1.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(
            OdinComponent::from_entry_name("PDA_S931U1.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(
            OdinComponent::from_entry_name("CP_S931U1UEU1AXB2.tar.md5"),
            Some(OdinComponent::Cp)
        );
        assert_eq!(
            OdinComponent::from_entry_name("MODEM_S931U1.tar.md5"),
            Some(OdinComponent::Cp)
        );
        assert_eq!(
            OdinComponent::from_entry_name("PHONE_S931U1.tar.md5"),
            Some(OdinComponent::Cp)
        );
        assert_eq!(
            OdinComponent::from_entry_name("CSC_OYM_S931U1OYM1AXB2.tar.md5"),
            Some(OdinComponent::Csc)
        );
        assert_eq!(
            OdinComponent::from_entry_name("HOME_CSC_OYM_S931U1OYM1AXB2.tar.md5"),
            Some(OdinComponent::HomeCsc)
        );
        assert_eq!(
            OdinComponent::from_entry_name("USERDATA_XAA_S931U1.tar.md5"),
            Some(OdinComponent::Userdata)
        );
        assert_eq!(
            OdinComponent::from_entry_name("I9305XXUEML8_I9305QLBEML4_HOME.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(
            OdinComponent::from_entry_name("dir\\home_csc_test.tar"),
            Some(OdinComponent::HomeCsc)
        );
        assert_eq!(OdinComponent::from_entry_name("SS_DL.dll"), None);
    }

    #[test]
    fn test_odin_component_all_and_keys() {
        let keys: Vec<_> = OdinComponent::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(keys, ["bl", "ap", "cp", "csc", "home_csc", "userdata"]);
    }
}
