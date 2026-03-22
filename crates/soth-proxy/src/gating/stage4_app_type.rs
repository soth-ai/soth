use soth_core::AppType;

use crate::gating::stage1_app_origin::IdentityMatch;

pub fn derive(identity: Option<&IdentityMatch>) -> AppType {
    identity
        .map(|matched| matched.entry.app_type)
        .unwrap_or(AppType::Unknown)
}
