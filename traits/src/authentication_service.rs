#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CredentialRef<'a> {
    Basic { identity: &'a [u8] },
    X509 { certificates: &'a [&'a [u8]] },
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub enum CredentialAuthenticationStatus {
    #[default]
    Unknown,
    Valid,
    Invalid,
    Expired,
    Revoked,
}

impl std::fmt::Display for CredentialAuthenticationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Valid => "valid",
                Self::Invalid => "invalid",
                Self::Expired => "expired",
                Self::Revoked => "revoked",
                Self::Unknown => "unknown",
            }
        )
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait AuthenticationServiceDelegate: std::fmt::Debug + Send + Sync {
    async fn validate_credential<'a>(
        &'a self,
        credential: CredentialRef<'a>,
    ) -> CredentialAuthenticationStatus;
}
