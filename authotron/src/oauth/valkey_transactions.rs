// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit shared authorization transactions and one-use code issuance/redemption.

use super::{
    authorization::ValidatedAuthorizationRequest,
    code_grant::{CodeGrant, CodeGrantError, MAX_CODE_GRANT_BYTES},
    codes::{AuthorizationCode, CodeIssueOutcome, CodeStoreError, IssuedCode, StoredCode},
    consent::{
        ConsentError, ConsentOutcome, ConsentSession, ConsentToken, MAX_CONSENT_SESSION_BYTES,
    },
    context::{AuthenticatedAuthorization, ContextError, MAX_AUTHENTICATED_CONTEXT_BYTES},
    records::{
        AuthorizationTransaction, BoundAuthorizationTransaction, MAX_TRANSACTION_BYTES, valid_time,
    },
    store::{
        ConsentStoreError, CreatedTransaction, RedeemedAuthorization, StoreError, TransactionId,
    },
};
use crate::{
    config::{OAuthConfig, ui::BrowserBackendConfig},
    utils::valkey::{ConnectionError, ValkeyConnection},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

pub struct ValkeyTransactionStore {
    config: Arc<OAuthConfig>,
    connection: ValkeyConnection,
    prefix: String,
    code_prefix: String,
}
#[derive(Clone, Copy)]
enum Operation {
    Create,
    Read,
    Consume,
    Promote,
    ReadAuthenticated,
    ConsumeAuthenticated,
    ReadForConsent,
    PrepareConsent,
    RenewConsent,
    ReadConsent,
    ConsumeConsent,
}
fn number(bytes: &[u8]) -> Result<u64, StoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(StoreError::Unavailable)
}
impl ValkeyTransactionStore {
    pub async fn new(
        config: Arc<OAuthConfig>,
        backend: &BrowserBackendConfig,
    ) -> Result<Self, StoreError> {
        config.validate().map_err(|_| StoreError::Configuration)?;
        if config
            .issuer
            .as_ref()
            .is_none_or(|issuer| issuer.len() > 2048)
        {
            return Err(StoreError::Configuration);
        }
        let BrowserBackendConfig::Valkey { key_prefix, .. } = backend else {
            return Err(StoreError::Configuration);
        };
        let connection = ValkeyConnection::connect(backend)
            .await
            .map_err(|error| match error {
                ConnectionError::Configuration => StoreError::Configuration,
                ConnectionError::Unavailable => StoreError::Unavailable,
            })?;
        Ok(Self {
            config,
            connection,
            prefix: format!("{key_prefix}:oauth:authorization-transactions:v3:"),
            code_prefix: format!("{key_prefix}:oauth:authorization-codes:v1:"),
        })
    }
    fn keys(&self, id: &TransactionId) -> [String; 2] {
        [
            format!("{}index", self.prefix),
            format!(
                "{}record:{}",
                self.prefix,
                URL_SAFE_NO_PAD.encode(id.hash())
            ),
        ]
    }
    fn code_keys(&self, code: &AuthorizationCode) -> [String; 2] {
        [
            format!("{}index", self.code_prefix),
            format!(
                "{}record:{}",
                self.code_prefix,
                URL_SAFE_NO_PAD.encode(code.hash())
            ),
        ]
    }
    async fn persist_code(
        &self,
        id: &TransactionId,
        code: &AuthorizationCode,
        record: &StoredCode,
        snapshot: (u64, &[u8], u64),
    ) -> Result<Vec<Vec<u8>>, CodeStoreError> {
        let (expiry, bytes, effective) = snapshot;
        if bytes.len() > MAX_CONSENT_SESSION_BYTES
            || record.payload().len() > MAX_CODE_GRANT_BYTES
            || record.code_hash() != &code.hash()
        {
            return Err(CodeStoreError::Unavailable);
        }
        self.connection
            .query(
                redis::cmd("EVAL")
                    .arg(include_str!("valkey_issue_code.lua"))
                    .arg(4)
                    .arg(&self.keys(id))
                    .arg(&self.code_keys(code))
                    .arg(expiry)
                    .arg(bytes)
                    .arg(effective)
                    .arg(self.config.max_authorization_codes)
                    .arg(record.expires_at_ms())
                    .arg(URL_SAFE_NO_PAD.encode(record.code_hash()))
                    .arg(record.issuer())
                    .arg(record.payload())
                    .arg(MAX_CODE_GRANT_BYTES)
                    .arg(MAX_CONSENT_SESSION_BYTES)
                    .arg(self.config.authorization_code_ttl_seconds * 1000),
            )
            .await
            .map_err(|_| CodeStoreError::Unavailable)
    }
    async fn code_command(
        &self,
        op: &str,
        code: &AuthorizationCode,
        snapshot: Option<(&StoredCode, u64)>,
    ) -> Result<Vec<Vec<u8>>, CodeStoreError> {
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(include_str!("valkey_redeem_code.lua"))
            .arg(2)
            .arg(&self.code_keys(code))
            .arg(op)
            .arg(MAX_CODE_GRANT_BYTES);
        if let Some((record, effective)) = snapshot {
            cmd.arg(record.expires_at_ms())
                .arg(URL_SAFE_NO_PAD.encode(record.code_hash()))
                .arg(record.issuer())
                .arg(record.payload())
                .arg(effective);
        }
        self.connection
            .query(&cmd)
            .await
            .map_err(|_| CodeStoreError::Unavailable)
    }
    async fn validated_code(
        &self,
        code: &AuthorizationCode,
        inputs: (&str, &str, &str, &str),
    ) -> Result<(StoredCode, CodeGrant), CodeStoreError> {
        use CodeStoreError::*;
        let reply = self.code_command("read", code, None).await?;
        let (now, record) = match reply.as_slice() {
            [status, now, expiry, hash, issuer, payload] if status == b"ok" => {
                let text = |bytes| std::str::from_utf8(bytes).map_err(|_| Unavailable);
                (
                    number(now).map_err(|_| Unavailable)?,
                    StoredCode::from_backend(
                        text(hash)?,
                        text(issuer)?,
                        number(expiry).map_err(|_| Unavailable)?,
                        payload,
                    )?,
                )
            }
            [status] if status == b"missing" => return Err(Missing),
            _ => return Err(Unavailable),
        };
        let grant = record.grant(code, &self.config, now)?;
        let (client, callback, resource, verifier) = inputs;
        grant
            .validate_redemption(client, callback, resource, verifier, &self.config, now)
            .map_err(|error| match error {
                CodeGrantError::InvalidRedemption | CodeGrantError::Expired => Missing,
                _ => Unavailable,
            })?;
        Ok((record, grant))
    }
    async fn consume_code(
        &self,
        code: &AuthorizationCode,
        record: StoredCode,
        grant: CodeGrant,
    ) -> Result<RedeemedAuthorization, CodeStoreError> {
        let reply = self
            .code_command("consume", code, Some((&record, grant.expires_at_ms())))
            .await?;
        match reply.as_slice() {
            [status] if status == b"ok" => Ok(RedeemedAuthorization::from_consumed(
                grant,
                record.issuer().into(),
            )),
            [status] if status == b"missing" => Err(CodeStoreError::Missing),
            _ => Err(CodeStoreError::Unavailable),
        }
    }
    pub async fn redeem_code(
        &self,
        code: &AuthorizationCode,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        code_verifier: &str,
    ) -> Result<RedeemedAuthorization, CodeStoreError> {
        let (record, grant) = self
            .validated_code(code, (client_id, redirect_uri, resource, code_verifier))
            .await?;
        self.consume_code(code, record, grant).await
    }
    pub async fn issue_code(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        submitted_csrf: &str,
        decision: &str,
    ) -> Result<CodeIssueOutcome, CodeStoreError> {
        self.issue_code_with(
            id,
            browser_hash,
            submitted_csrf,
            decision,
            AuthorizationCode::generate,
        )
        .await
    }
    async fn issue_code_with(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        submitted_csrf: &str,
        decision: &str,
        mut generate: impl FnMut() -> Result<AuthorizationCode, CodeStoreError>,
    ) -> Result<CodeIssueOutcome, CodeStoreError> {
        use CodeStoreError::*;
        let (outcome, expiry, bytes, effective, now) = self
            .consent_decision(id, browser_hash, submitted_csrf, decision)
            .await
            .map_err(|error| match error {
                ConsentStoreError::Missing => Missing,
                ConsentStoreError::InvalidToken => InvalidToken,
                ConsentStoreError::InvalidDecision => InvalidDecision,
                ConsentStoreError::Unavailable => Unavailable,
            })?;
        let ConsentOutcome::Approved(approval) = outcome else {
            Self::mutation(
                self.call(
                    Operation::ConsumeConsent,
                    id,
                    expiry,
                    &bytes,
                    Some((effective, &[])),
                )
                .await
                .map_err(|_| Unavailable)?,
            )
            .map_err(|error| {
                if error == StoreError::Missing {
                    Missing
                } else {
                    Unavailable
                }
            })?;
            return Ok(CodeIssueOutcome::Denied);
        };
        let grant = CodeGrant::from_consent(*approval, &self.config, id, browser_hash, now)
            .map_err(|_| Unavailable)?;
        let payload = grant.encode().map_err(|_| Unavailable)?;
        let issuer = self.config.issuer.as_deref().ok_or(Unavailable)?;
        for _ in 0..4 {
            let code = generate()?;
            let record = StoredCode::from_backend(
                &URL_SAFE_NO_PAD.encode(code.hash()),
                issuer,
                grant.expires_at_ms(),
                &payload,
            )?;
            let reply = self
                .persist_code(id, &code, &record, (expiry, &bytes, effective))
                .await?;
            match reply.as_slice() {
                [status] if status == b"ok" => {
                    return Ok(CodeIssueOutcome::Issued(IssuedCode::new(code, &grant)));
                }
                [status] if status == b"collision" => continue,
                [status] if status == b"limited" => return Err(Limited),
                [status] if status == b"missing" => return Err(Missing),
                _ => return Err(Unavailable),
            }
        }
        Err(Unavailable)
    }
    async fn call(
        &self,
        op: Operation,
        id: &TransactionId,
        expiry: u64,
        payload: &[u8],
        transition_guard: Option<(u64, &[u8])>,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let (tag, kind, limit) = match op {
            Operation::Create => ("create", "pending", MAX_TRANSACTION_BYTES),
            Operation::Read => ("read", "pending", MAX_TRANSACTION_BYTES),
            Operation::Consume => ("consume", "pending", MAX_TRANSACTION_BYTES),
            Operation::Promote => ("promote", "pending", MAX_AUTHENTICATED_CONTEXT_BYTES),
            Operation::ReadAuthenticated => {
                ("read", "authenticated", MAX_AUTHENTICATED_CONTEXT_BYTES)
            }
            Operation::ConsumeAuthenticated => {
                ("consume", "authenticated", MAX_AUTHENTICATED_CONTEXT_BYTES)
            }
            Operation::ReadForConsent => ("read", "prepare", MAX_CONSENT_SESSION_BYTES),
            Operation::PrepareConsent => ("prepare", "authenticated", MAX_CONSENT_SESSION_BYTES),
            Operation::RenewConsent => ("prepare", "consent", MAX_CONSENT_SESSION_BYTES),
            Operation::ReadConsent => ("read", "consent", MAX_CONSENT_SESSION_BYTES),
            Operation::ConsumeConsent => ("consume", "consent", MAX_CONSENT_SESSION_BYTES),
        };
        // Transitions guard the original snapshot; typed consumption instead guards
        // the recomputed freshness deadline, in addition to the stored expiry.
        let (guard_deadline, guard_payload) = transition_guard.unwrap_or((0, &[]));
        let guard_limit = match op {
            Operation::PrepareConsent => MAX_AUTHENTICATED_CONTEXT_BYTES,
            Operation::RenewConsent => MAX_CONSENT_SESSION_BYTES,
            _ => MAX_TRANSACTION_BYTES,
        };
        if payload.len() > limit || guard_payload.len() > guard_limit {
            return Err(StoreError::Unavailable);
        }
        self.connection
            .query(
                redis::cmd("EVAL")
                    .arg(include_str!("valkey_transactions.lua"))
                    .arg(2)
                    .arg(&self.keys(id))
                    .arg(tag)
                    .arg(MAX_TRANSACTION_BYTES)
                    .arg(self.config.authorization_transaction_ttl_seconds * 1000)
                    .arg(self.config.max_authorization_transactions)
                    .arg(expiry)
                    .arg(payload)
                    .arg(kind)
                    .arg(MAX_AUTHENTICATED_CONTEXT_BYTES)
                    .arg(guard_deadline)
                    .arg(guard_payload)
                    .arg(MAX_CONSENT_SESSION_BYTES),
            )
            .await
            .map_err(|_| StoreError::Unavailable)
    }
    pub async fn create(
        &self,
        request: ValidatedAuthorizationRequest,
        browser_hash: [u8; 32],
    ) -> Result<CreatedTransaction, StoreError> {
        let (seconds, micros): (u64, u64) = self
            .connection
            .query(&redis::cmd("TIME"))
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let now = seconds
            .checked_mul(1000)
            .and_then(|ms| ms.checked_add(micros / 1000))
            .filter(|now| micros < 1000000 && valid_time(*now))
            .ok_or(StoreError::Unavailable)?;
        let expiry = now
            .checked_add(self.config.authorization_transaction_ttl_seconds * 1000)
            .ok_or(StoreError::Unavailable)?;
        let bytes = AuthorizationTransaction::new(request, browser_hash, expiry)
            .and_then(|record| record.encode())
            .map_err(|_| StoreError::Unavailable)?;
        AuthorizationTransaction::decode(&bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        for _ in 0..4 {
            let id = TransactionId::generate()?;
            match self
                .call(Operation::Create, &id, expiry, &bytes, None)
                .await?
                .as_slice()
            {
                [status] if status == b"ok" => {
                    return Ok(CreatedTransaction {
                        id,
                        expires_at_ms: expiry,
                    });
                }
                [status] if status == b"limited" => return Err(StoreError::Limited),
                [status] if status == b"collision" => continue,
                _ => return Err(StoreError::Unavailable),
            }
        }
        Err(StoreError::Unavailable)
    }
    async fn read(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<(AuthorizationTransaction, Vec<u8>, u64), StoreError> {
        let (now, expiry, bytes, _) = self.raw_read(id, Operation::Read).await?;
        let record = AuthorizationTransaction::decode(&bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        if record.expires_at_ms() != expiry {
            return Err(StoreError::Unavailable);
        }
        if !record.matches_browser_binding(browser_hash) {
            return Err(StoreError::Missing);
        }
        Ok((record, bytes, now))
    }
    async fn raw_read(
        &self,
        id: &TransactionId,
        op: Operation,
    ) -> Result<(u64, u64, Vec<u8>, Vec<u8>), StoreError> {
        let reply = self.call(op, id, 0, &[], None).await?;
        match reply.as_slice() {
            [status, now, expiry, bytes, kind] if status == b"ok" => {
                Ok((number(now)?, number(expiry)?, bytes.clone(), kind.clone()))
            }
            [status] if status == b"missing" => Err(StoreError::Missing),
            _ => Err(StoreError::Unavailable),
        }
    }
    pub async fn lookup(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        self.read(id, browser_hash)
            .await
            .map(|(record, _, _)| record)
    }
    pub async fn lookup_bound(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<BoundAuthorizationTransaction, StoreError> {
        let transaction = self.lookup(id, browser_hash).await?;
        Ok(BoundAuthorizationTransaction::from_store(
            transaction,
            id.hash(),
        ))
    }
    pub async fn consume(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        let (record, bytes, _) = self.read(id, browser_hash).await?;
        match self
            .call(Operation::Consume, id, record.expires_at_ms(), &bytes, None)
            .await?
            .as_slice()
        {
            [status] if status == b"ok" => Ok(record),
            [status] if status == b"missing" => Err(StoreError::Missing),
            _ => Err(StoreError::Unavailable),
        }
    }
    pub async fn promote_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        context: AuthenticatedAuthorization,
    ) -> Result<(), StoreError> {
        let (pending, original, now) = self.read(id, browser_hash).await?;
        if !context.matches_source(&id.hash())
            || context
                .transaction()
                .encode()
                .map_err(|_| StoreError::Unavailable)?
                != original
        {
            return Err(StoreError::Unavailable);
        }
        let bytes = context.encode().map_err(|_| StoreError::Unavailable)?;
        let checked = AuthenticatedAuthorization::decode(&bytes, &self.config, browser_hash, now)
            .map_err(|_| StoreError::Unavailable)?;
        if checked.expires_at_ms() > pending.expires_at_ms() {
            return Err(StoreError::Unavailable);
        }
        Self::mutation(
            self.call(
                Operation::Promote,
                id,
                checked.expires_at_ms(),
                &bytes,
                Some((pending.expires_at_ms(), &original)),
            )
            .await?,
        )
    }
    fn mutation(reply: Vec<Vec<u8>>) -> Result<(), StoreError> {
        match reply.as_slice() {
            [status] if status == b"ok" => Ok(()),
            [status] if status == b"missing" => Err(StoreError::Missing),
            _ => Err(StoreError::Unavailable),
        }
    }
    async fn read_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<(AuthenticatedAuthorization, u64, Vec<u8>), StoreError> {
        let (now, expiry, bytes, _) = self.raw_read(id, Operation::ReadAuthenticated).await?;
        let context = AuthenticatedAuthorization::decode(&bytes, &self.config, browser_hash, now)
            .map_err(|error| match error {
            ContextError::Binding => StoreError::Missing,
            _ => StoreError::Unavailable,
        })?;
        if !context.matches_source(&id.hash()) || context.expires_at_ms() > expiry {
            return Err(StoreError::Unavailable);
        }
        Ok((context, expiry, bytes))
    }
    pub async fn lookup_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        self.read_authenticated(id, browser_hash)
            .await
            .map(|(context, _, _)| context)
    }
    pub async fn consume_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        let (context, expiry, bytes) = self.read_authenticated(id, browser_hash).await?;
        Self::mutation(
            self.call(
                Operation::ConsumeAuthenticated,
                id,
                expiry,
                &bytes,
                Some((context.expires_at_ms(), &[])),
            )
            .await?,
        )?;
        Ok(context)
    }
    async fn consent_candidate(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<(Operation, ConsentSession, ConsentToken, u64, Vec<u8>), StoreError> {
        let (now, expiry, original, kind) = self.raw_read(id, Operation::ReadForConsent).await?;
        let (op, result) = if kind == b"authenticated" {
            let context =
                AuthenticatedAuthorization::decode(&original, &self.config, browser_hash, now)
                    .map_err(|error| match error {
                        ContextError::Binding => StoreError::Missing,
                        _ => StoreError::Unavailable,
                    })?;
            if !context.matches_source(&id.hash()) {
                return Err(StoreError::Unavailable);
            }
            (
                Operation::PrepareConsent,
                ConsentSession::from_stored_context(
                    context,
                    id,
                    &self.config,
                    browser_hash,
                    now,
                    expiry,
                ),
            )
        } else if kind == b"consent" {
            let session = ConsentSession::decode(&original, id, &self.config, browser_hash, now)
                .map_err(|_| StoreError::Unavailable)?;
            if session.expires_at_ms() > expiry {
                return Err(StoreError::Unavailable);
            }
            (
                Operation::RenewConsent,
                session.renew(id, &self.config, browser_hash, now),
            )
        } else {
            return Err(StoreError::Missing);
        };
        let (session, token) = result.map_err(|_| StoreError::Unavailable)?;
        Ok((op, session, token, expiry, original))
    }
    pub async fn prepare_consent(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<ConsentToken, StoreError> {
        let (op, session, token, expiry, original) =
            self.consent_candidate(id, browser_hash).await?;
        let bytes = session.encode().map_err(|_| StoreError::Unavailable)?;
        Self::mutation(
            self.call(
                op,
                id,
                session.expires_at_ms(),
                &bytes,
                Some((expiry, &original)),
            )
            .await?,
        )?;
        Ok(token)
    }
    pub(super) async fn consent_context(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        let (now, expiry, bytes, _) = self.raw_read(id, Operation::ReadConsent).await?;
        let session = ConsentSession::decode(&bytes, id, &self.config, binding, now)
            .map_err(|_| StoreError::Unavailable)?;
        if session.expires_at_ms() > expiry {
            return Err(StoreError::Unavailable);
        }
        Ok(session.into_context())
    }
    pub(crate) async fn server_now_ms(&self) -> Result<u64, StoreError> {
        let (sec, micro): (u64, u64) = self
            .connection
            .query(&redis::cmd("TIME"))
            .await
            .map_err(|_| StoreError::Unavailable)?;
        sec.checked_mul(1000)
            .and_then(|ms| ms.checked_add(micro / 1000))
            .filter(|ms| micro < 1000000 && valid_time(*ms))
            .ok_or(StoreError::Unavailable)
    }
    async fn consent_decision(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        submitted: &str,
        decision: &str,
    ) -> Result<(ConsentOutcome, u64, Vec<u8>, u64, u64), ConsentStoreError> {
        use ConsentStoreError::*;
        let (now, expiry, bytes, _) =
            self.raw_read(id, Operation::ReadConsent)
                .await
                .map_err(|error| match error {
                    StoreError::Missing => Missing,
                    _ => Unavailable,
                })?;
        let session = ConsentSession::decode(&bytes, id, &self.config, browser_hash, now)
            .map_err(|_| Unavailable)?;
        let effective = session.expires_at_ms();
        if effective > expiry {
            return Err(Unavailable);
        }
        let outcome = session
            .decide(submitted, decision, id, browser_hash, &self.config, now)
            .map_err(|error| match error {
                ConsentError::InvalidToken => InvalidToken,
                ConsentError::InvalidDecision => InvalidDecision,
                _ => Unavailable,
            })?;
        Ok((outcome, expiry, bytes, effective, now))
    }
    pub async fn decide_consent(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        submitted_csrf: &str,
        decision: &str,
    ) -> Result<ConsentOutcome, ConsentStoreError> {
        let (outcome, expiry, bytes, effective, _) = self
            .consent_decision(id, browser_hash, submitted_csrf, decision)
            .await?;
        Self::mutation(
            self.call(
                Operation::ConsumeConsent,
                id,
                expiry,
                &bytes,
                Some((effective, &[])),
            )
            .await
            .map_err(|_| ConsentStoreError::Unavailable)?,
        )
        .map_err(|error| match error {
            StoreError::Missing => ConsentStoreError::Missing,
            _ => ConsentStoreError::Unavailable,
        })?;
        // An already computed capability is returned only after the atomic delete succeeds.
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::super::store::tests::{config, request};
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    fn docker(args: &[&str]) -> String {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI required");
        assert!(
            output.status.success(),
            "disposable Valkey fixture {} command failed",
            args[0]
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
    async fn command<T: redis::FromRedisValue>(
        store: &ValkeyTransactionStore,
        command: &redis::Cmd,
    ) -> T {
        store.connection.query(command).await.unwrap()
    }
    async fn code_source(store: &ValkeyTransactionStore) -> (CreatedTransaction, ConsentToken) {
        let (_, _, identity) = super::super::context::tests::fixture().await;
        let callback = &store.config.clients[0].redirect_uris[0];
        let query = format!(
            "client_id=desktop&redirect_uri={callback}&response_type=code&resource=https://mcp.example.org/mcp&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
        );
        let request = super::super::authorization::validate_authorization_request(
            &store.config,
            query.as_bytes(),
        )
        .unwrap();
        let created = store.create(request, [7; 32]).await.unwrap();
        let source = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (sec, micro): (u64, u64) = command(store, &redis::cmd("TIME")).await;
        let context = AuthenticatedAuthorization::new_bound(
            source,
            identity,
            &[7; 32],
            &store.config,
            sec * 1000 + micro / 1000,
        )
        .unwrap();
        store
            .promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let token = store.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        (created, token)
    }
    async fn issued_shared(store: &ValkeyTransactionStore) -> IssuedCode {
        let (source, csrf) = code_source(store).await;
        let CodeIssueOutcome::Issued(code) = store
            .issue_code(&source.id, &[7; 32], csrf.as_secret_str(), "approve")
            .await
            .unwrap()
        else {
            panic!("issued code required")
        };
        code
    }
    async fn redemption_cases(backend: &BrowserBackendConfig) {
        use CodeStoreError::*;
        let (mut cfg, _, _) = super::super::context::tests::fixture().await;
        cfg.issuer = Some("https://login.example.org/".into());
        cfg.max_authorization_codes = 1;
        cfg.clients[0].application_type = crate::config::oauth::ApplicationType::Native;
        cfg.clients[0].redirect_uris = vec!["http://127.0.0.1:49152/cb".into()];
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let b = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let code = issued_shared(&a).await;
        let keys = a.code_keys(code.code());
        let inputs = (
            "desktop",
            code.redirect_uri(),
            "https://mcp.example.org/mcp",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        );
        let original = a.code_command("read", code.code(), None).await.unwrap();
        let before: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        for bad in [
            ("other", inputs.1, inputs.2, inputs.3),
            (inputs.0, "http://127.0.0.1:49153/cb", inputs.2, inputs.3),
            (inputs.0, "http://127.0.0.1:49152/CB", inputs.2, inputs.3),
            (inputs.0, inputs.1, "https://mcp.example.org/mcp/", inputs.3),
            (inputs.0, inputs.1, inputs.2, &"x".repeat(43)),
            (inputs.0, inputs.1, inputs.2, "short"),
        ] {
            assert_eq!(
                b.redeem_code(code.code(), bad.0, bad.1, bad.2, bad.3)
                    .await
                    .err(),
                Some(Missing)
            );
        }
        let mut variant = (*cfg).clone();
        variant.issuer = Some("https://login.example.org".into());
        let variant = ValkeyTransactionStore::new(Arc::new(variant), backend)
            .await
            .unwrap();
        assert_eq!(
            variant.validated_code(code.code(), inputs).await.err(),
            Some(Unavailable)
        );
        for op in ["del", "zrem"] {
            let _: String = command(
                &a,
                redis::cmd("ACL")
                    .arg("SETUSER")
                    .arg("default")
                    .arg(format!("-{op}")),
            )
            .await;
            assert_eq!(
                b.redeem_code(code.code(), inputs.0, inputs.1, inputs.2, inputs.3)
                    .await
                    .err(),
                Some(Unavailable)
            );
            let _: String = command(
                &a,
                redis::cmd("ACL")
                    .arg("SETUSER")
                    .arg("default")
                    .arg(format!("+{op}")),
            )
            .await;
        }
        let current = a.code_command("read", code.code(), None).await.unwrap();
        assert!(current[2..] == original[2..]);
        let after: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(after > 0 && after <= before);
        // Force validated snapshots to precede changes in every CAS-protected field.
        for field in ["code_hash", "issuer", "payload", "expiry"] {
            let (record, grant) = a.validated_code(code.code(), inputs).await.unwrap();
            let old: Vec<u8> = command(&a, redis::cmd("HGET").arg(&keys[1]).arg(field)).await;
            let changed = match field {
                "code_hash" => URL_SAFE_NO_PAD
                    .encode(AuthorizationCode::generate().unwrap().hash())
                    .into_bytes(),
                "issuer" => b"https://other.example.org/".to_vec(),
                "expiry" => (record.expires_at_ms() - 1).to_string().into_bytes(),
                _ => b"{}".to_vec(),
            };
            let _: usize = command(
                &a,
                redis::cmd("HSET").arg(&keys[1]).arg(field).arg(&changed),
            )
            .await;
            if field == "expiry" {
                let _: usize = command(
                    &a,
                    redis::cmd("ZADD")
                        .arg(&keys[0])
                        .arg(record.expires_at_ms() - 1)
                        .arg(&keys[1]),
                )
                .await;
            }
            assert_eq!(
                a.consume_code(code.code(), record, grant).await.err(),
                Some(Missing)
            );
            let _: usize = command(&a, redis::cmd("HSET").arg(&keys[1]).arg(field).arg(old)).await;
            let _: usize = command(
                &a,
                redis::cmd("ZADD")
                    .arg(&keys[0])
                    .arg(code.expires_at_ms())
                    .arg(&keys[1]),
            )
            .await;
        }
        let mut unsupported: serde_json::Value = serde_json::from_slice(&original[5]).unwrap();
        unsupported["version"] = serde_json::json!(2);
        for (field, changed) in [
            ("code_hash", b"bad".to_vec()),
            (
                "code_hash",
                URL_SAFE_NO_PAD
                    .encode(AuthorizationCode::generate().unwrap().hash())
                    .into_bytes(),
            ),
            ("payload", vec![b'x'; MAX_CODE_GRANT_BYTES + 1]),
            ("payload", b"{}".to_vec()),
            ("payload", serde_json::to_vec(&unsupported).unwrap()),
            ("issuer", b"http://invalid.example.org".to_vec()),
            ("issuer", vec![b'x'; 2049]),
            ("expiry", b"2534023007999999".to_vec()),
        ] {
            let old: Vec<u8> = command(&a, redis::cmd("HGET").arg(&keys[1]).arg(field)).await;
            let _: usize =
                command(&a, redis::cmd("HSET").arg(&keys[1]).arg(field).arg(changed)).await;
            assert_eq!(
                a.validated_code(code.code(), inputs).await.err(),
                Some(Unavailable)
            );
            let _: usize = command(&a, redis::cmd("HSET").arg(&keys[1]).arg(field).arg(old)).await;
        }
        let _: usize = command(
            &a,
            redis::cmd("HSET").arg(&keys[1]).arg("extra").arg("invalid"),
        )
        .await;
        assert_eq!(
            a.validated_code(code.code(), inputs).await.err(),
            Some(Unavailable)
        );
        let _: usize = command(&a, redis::cmd("HDEL").arg(&keys[1]).arg("extra")).await;
        for field in ["code_hash", "issuer", "expiry", "payload"] {
            let old: Vec<u8> = command(&a, redis::cmd("HGET").arg(&keys[1]).arg(field)).await;
            let _: usize = command(&a, redis::cmd("HDEL").arg(&keys[1]).arg(field)).await;
            assert_eq!(
                a.validated_code(code.code(), inputs).await.err(),
                Some(Unavailable)
            );
            let _: usize = command(&a, redis::cmd("HSET").arg(&keys[1]).arg(field).arg(old)).await;
        }
        let _: usize = command(
            &a,
            redis::cmd("ZADD")
                .arg(&keys[0])
                .arg(code.expires_at_ms() + 1)
                .arg(&keys[1]),
        )
        .await;
        assert_eq!(
            a.validated_code(code.code(), inputs).await.err(),
            Some(Unavailable)
        );
        let _: usize = command(
            &a,
            redis::cmd("ZADD")
                .arg(&keys[0])
                .arg(code.expires_at_ms())
                .arg(&keys[1]),
        )
        .await;
        let backup = format!("{}:backup", keys[0]);
        let _: String = command(&a, redis::cmd("RENAME").arg(&keys[0]).arg(&backup)).await;
        let _: String = command(&a, redis::cmd("SET").arg(&keys[0]).arg("wrong-type")).await;
        assert_eq!(
            a.validated_code(code.code(), inputs).await.err(),
            Some(Unavailable)
        );
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys[0])).await;
        let _: String = command(&a, redis::cmd("RENAME").arg(&backup).arg(&keys[0])).await;
        let proof = b
            .redeem_code(code.code(), inputs.0, inputs.1, inputs.2, inputs.3)
            .await
            .unwrap();
        assert_eq!(proof.issuer(), cfg.issuer.as_deref().unwrap());
        assert_eq!(proof.grant().scopes(), ["read"]);
        assert_eq!(
            a.validated_code(code.code(), inputs).await.err(),
            Some(Missing)
        );
        // A fresh issuance demonstrates freed shared capacity, then both reads finish before CAS.
        let code = issued_shared(&a).await;
        let (left_record, left_grant) = a.validated_code(code.code(), inputs).await.unwrap();
        let (right_record, right_grant) = b.validated_code(code.code(), inputs).await.unwrap();
        let (left, right) = tokio::join!(
            a.consume_code(code.code(), left_record, left_grant),
            b.consume_code(code.code(), right_record, right_grant)
        );
        let results = [left, right];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(Missing)))
                .count(),
            1
        );
        let code = issued_shared(&a).await;
        let mut tighter = (*cfg).clone();
        tighter.max_authentication_age_seconds = 1;
        let tighter = ValkeyTransactionStore::new(Arc::new(tighter), backend)
            .await
            .unwrap();
        let (record, grant) = tighter.validated_code(code.code(), inputs).await.unwrap();
        let effective = grant.expires_at_ms();
        assert!(effective < record.expires_at_ms());
        let (sec, micro): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let now = sec * 1000 + micro / 1000;
        assert!(now < effective);
        tokio::time::sleep(Duration::from_millis(effective - now + 20)).await;
        assert_eq!(
            tighter.consume_code(code.code(), record, grant).await.err(),
            Some(Missing)
        );
        assert!(a.validated_code(code.code(), inputs).await.is_ok());
        assert!(
            a.redeem_code(code.code(), inputs.0, inputs.1, inputs.2, inputs.3)
                .await
                .is_ok()
        );
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 0);
    }
    async fn code_cases(backend: &BrowserBackendConfig) {
        use CodeStoreError::*;
        let (mut cfg, _, _) = super::super::context::tests::fixture().await;
        cfg.issuer = Some("https://login.example.org/".into());
        cfg.max_authorization_transactions = 1;
        cfg.max_authorization_codes = 1;
        cfg.authorization_code_ttl_seconds = 30;
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let b = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let (source, token) = code_source(&a).await;
        let (_, _, original, _) = a
            .raw_read(&source.id, Operation::ReadConsent)
            .await
            .unwrap();
        // Allow ZADD only in the source namespace; code-index ZADD is denied specifically.
        let selector = format!("(+zadd ~{}*)", a.prefix);
        let _: String = command(
            &a,
            redis::cmd("ACL")
                .arg("SETUSER")
                .arg("default")
                .arg("-zadd")
                .arg(selector),
        )
        .await;
        for restore in [false, true] {
            if restore {
                let _: String = command(
                    &a,
                    redis::cmd("ACL").arg(&[
                        "SETUSER",
                        "default",
                        "clearselectors",
                        "+zadd",
                        "-del",
                    ]),
                )
                .await;
            }
            assert_eq!(
                b.issue_code(&source.id, &[7; 32], token.as_secret_str(), "approve")
                    .await
                    .err(),
                Some(Unavailable)
            );
            let (_, _, preserved, _) = a
                .raw_read(&source.id, Operation::ReadConsent)
                .await
                .unwrap();
            assert!(preserved == original);
            let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
            assert_eq!(count, 2);
        }
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "+del"])).await;
        let (left, right) = tokio::join!(
            a.issue_code(&source.id, &[7; 32], token.as_secret_str(), "approve"),
            b.issue_code(&source.id, &[7; 32], token.as_secret_str(), "approve")
        );
        let outcomes = [left, right];
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(Missing)))
                .count(),
            1
        );
        let mut winners = outcomes.into_iter().filter_map(|result| match result {
            Ok(CodeIssueOutcome::Issued(code)) => Some(code),
            _ => None,
        });
        let code = winners.next().unwrap();
        assert!(winners.next().is_none());
        assert_eq!(
            a.prepare_consent(&source.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            b.issue_code(&source.id, &[7; 32], token.as_secret_str(), "approve")
                .await
                .err(),
            Some(Missing)
        );
        let keys = a.code_keys(code.code());
        assert!(keys[1].starts_with(&format!("{}record:", a.code_prefix)));
        let mut fields: Vec<String> = command(&a, redis::cmd("HKEYS").arg(&keys[1])).await;
        fields.sort();
        assert_eq!(fields, ["code_hash", "expiry", "issuer", "payload"]);
        let size: usize = command(&a, redis::cmd("HSTRLEN").arg(&keys[1]).arg("payload")).await;
        assert!(size > 0 && size <= MAX_CODE_GRANT_BYTES);
        let hash: String = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("code_hash")).await;
        let issuer: String = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("issuer")).await;
        let expiry: u64 = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("expiry")).await;
        let payload: Vec<u8> = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("payload")).await;
        let record = StoredCode::from_backend(&hash, &issuer, expiry, &payload).unwrap();
        assert_eq!(record.code_hash(), &code.code().hash());
        assert_eq!(record.issuer(), "https://login.example.org/");
        assert_eq!(expiry, code.expires_at_ms());
        assert!(expiry <= source.expires_at_ms);
        let (sec, micro): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let grant = record
            .grant(code.code(), &cfg, sec * 1000 + micro / 1000)
            .unwrap();
        assert_eq!(expiry, grant.issued_at_ms() + 30_000);
        assert!(
            !std::str::from_utf8(&payload)
                .unwrap()
                .contains(code.code().as_secret_str())
        );
        assert!(
            !std::str::from_utf8(&payload)
                .unwrap()
                .contains(token.as_secret_str())
        );
        let ttl: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(ttl > 0 && ttl <= 30_000);
        let score: u64 = command(&a, redis::cmd("ZSCORE").arg(&keys[0]).arg(&keys[1])).await;
        assert_eq!(score, expiry);
        let count: usize = command(&a, redis::cmd("ZCARD").arg(&keys[0])).await;
        assert_eq!(count, 1);
        let (second, token) = code_source(&b).await;
        let (_, _, original, _) = a
            .raw_read(&second.id, Operation::ReadConsent)
            .await
            .unwrap();
        let mut attempts = 0;
        let result = a
            .issue_code_with(
                &second.id,
                &[7; 32],
                token.as_secret_str(),
                "approve",
                || {
                    attempts += 1;
                    AuthorizationCode::parse(code.code().as_secret_str())
                },
            )
            .await;
        assert_eq!(result.err(), Some(Unavailable));
        assert_eq!(attempts, 4);
        assert_eq!(
            b.issue_code(&second.id, &[7; 32], token.as_secret_str(), "approve")
                .await
                .err(),
            Some(Limited)
        );
        let (_, _, preserved, _) = a
            .raw_read(&second.id, Operation::ReadConsent)
            .await
            .unwrap();
        assert!(preserved == original);
        assert!(matches!(
            a.issue_code(&second.id, &[7; 32], token.as_secret_str(), "deny")
                .await
                .unwrap(),
            CodeIssueOutcome::Denied
        ));
        let count: usize = command(&a, redis::cmd("ZCARD").arg(&keys[0])).await;
        assert_eq!(count, 1);
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys)).await;
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 0);
    }
    async fn consent_cases(backend: &BrowserBackendConfig) {
        let (mut cfg, _, identity) = super::super::context::tests::fixture().await;
        cfg.max_authorization_transactions = 1;
        cfg.authorization_transaction_ttl_seconds = 30;
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let b = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        let witness = b.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (sec, micro): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let context = AuthenticatedAuthorization::new_bound(
            witness,
            identity,
            &[7; 32],
            &cfg,
            sec * 1000 + micro / 1000,
        )
        .unwrap();
        a.promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let first = b.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        let second = a.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        let (_, expiry, bytes, _) = a
            .raw_read(&created.id, Operation::ReadConsent)
            .await
            .unwrap();
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(second.as_secret_str())
        );
        assert!(expiry <= created.expires_at_ms);
        let kind: String = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("kind")).await;
        assert_eq!(kind, "consent");
        let ttl: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(ttl > 0);
        let score: u64 = command(&a, redis::cmd("ZSCORE").arg(&keys[0]).arg(&keys[1])).await;
        assert_eq!(score, expiry);
        assert_eq!(
            a.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            a.lookup_authenticated(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            a.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Limited)
        );
        for (token, decision, binding, expected) in [
            (
                first.as_secret_str(),
                "approve",
                [7; 32],
                ConsentStoreError::InvalidToken,
            ),
            (
                second.as_secret_str(),
                "other",
                [7; 32],
                ConsentStoreError::InvalidDecision,
            ),
            (
                second.as_secret_str(),
                "approve",
                [8; 32],
                ConsentStoreError::Unavailable,
            ),
        ] {
            assert_eq!(
                b.decide_consent(&created.id, &binding, token, decision)
                    .await
                    .err(),
                Some(expected)
            );
        }
        let (_, _, unchanged, _) = a
            .raw_read(&created.id, Operation::ReadConsent)
            .await
            .unwrap();
        assert!(unchanged == bytes);
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "-hset"])).await;
        assert_eq!(
            a.prepare_consent(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let (_, _, unchanged, _) = a
            .raw_read(&created.id, Operation::ReadConsent)
            .await
            .unwrap();
        assert!(unchanged == bytes);
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "+hset"])).await;
        let (left_op, left_session, left_token, left_exp, left_bytes) =
            a.consent_candidate(&created.id, &[7; 32]).await.unwrap();
        let (right_op, right_session, right_token, right_exp, right_bytes) =
            b.consent_candidate(&created.id, &[7; 32]).await.unwrap();
        assert!(left_bytes == right_bytes && left_exp == right_exp);
        let left_wire = left_session.encode().unwrap();
        let right_wire = right_session.encode().unwrap();
        let (left, right) = tokio::join!(
            a.call(
                left_op,
                &created.id,
                left_session.expires_at_ms(),
                &left_wire,
                Some((left_exp, &left_bytes))
            ),
            b.call(
                right_op,
                &created.id,
                right_session.expires_at_ms(),
                &right_wire,
                Some((right_exp, &right_bytes))
            )
        );
        let left = left.unwrap();
        let right = right.unwrap();
        let left_won = matches!(left.as_slice(), [status] if status == b"ok");
        let right_won = matches!(right.as_slice(), [status] if status == b"ok");
        assert_ne!(left_won, right_won);
        let loser = if left_won { &right } else { &left };
        assert!(matches!(loser.as_slice(), [status] if status == b"missing"));
        let second = if left_won { left_token } else { right_token };
        // Force both validations to finish before competing CAS deletes.
        let (left, exp, payload, effective, _) = a
            .consent_decision(&created.id, &[7; 32], second.as_secret_str(), "approve")
            .await
            .unwrap();
        let (right, other_exp, other_payload, other_effective, _) = b
            .consent_decision(&created.id, &[7; 32], second.as_secret_str(), "approve")
            .await
            .unwrap();
        assert!(
            matches!(left, ConsentOutcome::Approved(_))
                && matches!(right, ConsentOutcome::Approved(_))
        );
        let (left, right) = tokio::join!(
            a.call(
                Operation::ConsumeConsent,
                &created.id,
                exp,
                &payload,
                Some((effective, &[]))
            ),
            b.call(
                Operation::ConsumeConsent,
                &created.id,
                other_exp,
                &other_payload,
                Some((other_effective, &[]))
            )
        );
        let replies = [left.unwrap(), right.unwrap()];
        assert_eq!(
            replies
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"ok"))
                .count(),
            1
        );
        assert_eq!(
            replies
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"missing"))
                .count(),
            1
        );
        assert_eq!(
            a.decide_consent(&created.id, &[7; 32], second.as_secret_str(), "approve")
                .await
                .err(),
            Some(ConsentStoreError::Missing)
        );
        // Fresh identities exercise public approval races and denial, releasing the same slot.
        for decision in ["approve", "deny"] {
            let (_, _, identity) = super::super::context::tests::fixture().await;
            let created = a.create(request(&cfg), [7; 32]).await.unwrap();
            let witness = a.lookup_bound(&created.id, &[7; 32]).await.unwrap();
            let (sec, micro): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
            let context = AuthenticatedAuthorization::new_bound(
                witness,
                identity,
                &[7; 32],
                &cfg,
                sec * 1000 + micro / 1000,
            )
            .unwrap();
            a.promote_authenticated(&created.id, &[7; 32], context)
                .await
                .unwrap();
            let token = b.prepare_consent(&created.id, &[7; 32]).await.unwrap();
            if decision == "approve" {
                let (left, right) = tokio::join!(
                    a.decide_consent(&created.id, &[7; 32], token.as_secret_str(), decision),
                    b.decide_consent(&created.id, &[7; 32], token.as_secret_str(), decision)
                );
                let outcomes = [left, right];
                assert_eq!(
                    outcomes
                        .iter()
                        .filter(|result| matches!(result, Ok(ConsentOutcome::Approved(_))))
                        .count(),
                    1
                );
                assert_eq!(
                    outcomes
                        .iter()
                        .filter(|result| matches!(result, Err(ConsentStoreError::Missing)))
                        .count(),
                    1
                );
            } else {
                assert!(matches!(
                    a.decide_consent(&created.id, &[7; 32], token.as_secret_str(), decision)
                        .await,
                    Ok(ConsentOutcome::Denied)
                ));
            }
        }
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 0);
    }
    async fn effective_deadline_and_hash_shape_cases(backend: &BrowserBackendConfig) {
        let (mut cfg, _, identity) = super::super::context::tests::fixture().await;
        cfg.max_authorization_transactions = 1;
        cfg.authorization_transaction_ttl_seconds = 30;
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        let witness = a.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let context = AuthenticatedAuthorization::new_bound(
            witness,
            identity,
            &[7; 32],
            &cfg,
            seconds * 1000 + micros / 1000,
        )
        .unwrap();
        a.promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let mut stricter = (*cfg).clone();
        stricter.max_authentication_age_seconds = 1;
        let b = ValkeyTransactionStore::new(Arc::new(stricter), backend)
            .await
            .unwrap();
        let (snapshot, stored_expiry, bytes) =
            b.read_authenticated(&created.id, &[7; 32]).await.unwrap();
        let effective = snapshot.expires_at_ms();
        assert!(effective < stored_expiry);
        assert_eq!(stored_expiry, created.expires_at_ms);
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let before = seconds * 1000 + micros / 1000;
        assert!(before < effective);
        tokio::time::sleep(Duration::from_millis(effective - before + 20)).await;
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let after = seconds * 1000 + micros / 1000;
        assert!(after >= effective && after < stored_expiry);
        let reply = b
            .call(
                Operation::ConsumeAuthenticated,
                &created.id,
                stored_expiry,
                &bytes,
                Some((effective, &[])),
            )
            .await
            .unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"missing"));
        let payload: Vec<u8> = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("payload")).await;
        assert!(payload == bytes);
        let kind: String = command(&a, redis::cmd("HGET").arg(&keys[1]).arg("kind")).await;
        assert_eq!(kind, "authenticated");
        let ttl: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(ttl > 0);
        let score: u64 = command(&a, redis::cmd("ZSCORE").arg(&keys[0]).arg(&keys[1])).await;
        assert_eq!(score, stored_expiry);
        assert_eq!(
            b.lookup_authenticated(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        assert!(a.lookup_authenticated(&created.id, &[7; 32]).await.is_ok());
        let _: usize = command(
            &a,
            redis::cmd("HSET")
                .arg(&keys[1])
                .arg("extra")
                .arg("invalid-shape"),
        )
        .await;
        assert_eq!(
            a.lookup_authenticated(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(&a, redis::cmd("HDEL").arg(&keys[1]).arg("extra")).await;
        for field in ["kind", "expiry", "payload"] {
            let _: usize = command(&a, redis::cmd("HDEL").arg(&keys[1]).arg(field)).await;
            assert_eq!(
                a.lookup_authenticated(&created.id, &[7; 32]).await.err(),
                Some(StoreError::Unavailable)
            );
            let _: usize = command(
                &a,
                redis::cmd("HSET")
                    .arg(&keys[1])
                    .arg("kind")
                    .arg("authenticated")
                    .arg("expiry")
                    .arg(stored_expiry)
                    .arg("payload")
                    .arg(&bytes),
            )
            .await;
        }
        assert!(a.consume_authenticated(&created.id, &[7; 32]).await.is_ok());
    }
    async fn authenticated_cases(backend: &BrowserBackendConfig) {
        let (mut cfg, _, identity) = super::super::context::tests::fixture().await;
        cfg.max_authorization_transactions = 1;
        cfg.max_authentication_age_seconds = 1;
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let b = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        let witness = b.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let context = AuthenticatedAuthorization::new_bound(
            witness,
            identity,
            &[7; 32],
            &cfg,
            seconds * 1000 + micros / 1000,
        )
        .unwrap();
        let saved = context.encode().unwrap();
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "-zadd"])).await;
        assert_eq!(
            a.promote_authenticated(&created.id, &[7; 32], context)
                .await
                .err(),
            Some(StoreError::Unavailable)
        );
        assert!(b.lookup(&created.id, &[7; 32]).await.is_ok());
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "+zadd"])).await;
        let context = AuthenticatedAuthorization::decode(
            &saved,
            &cfg,
            &[7; 32],
            seconds * 1000 + micros / 1000,
        )
        .unwrap();
        a.promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let again = AuthenticatedAuthorization::decode(
            &saved,
            &cfg,
            &[7; 32],
            seconds * 1000 + micros / 1000,
        )
        .unwrap();
        assert_eq!(
            b.promote_authenticated(&created.id, &[7; 32], again)
                .await
                .err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            b.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            b.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            b.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            b.consume_authenticated(&created.id, &[8; 32]).await.err(),
            Some(StoreError::Missing)
        );
        let ttl1: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let context = b.lookup_authenticated(&created.id, &[7; 32]).await.unwrap();
        assert_eq!(context.as_user().username, "alice");
        assert_eq!(context.authorized_scopes(), &["read"]);
        assert!(
            context.matches_source(&created.id.hash())
                && context.expires_at_ms() < created.expires_at_ms
        );
        let ttl2: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(ttl2 < ttl1 && ttl1 <= 1030 && ttl2 > 0);
        let mut denied = (*cfg).clone();
        denied.resources[0].scopes[0]
            .required_roles
            .push("absent".into());
        let denied = ValkeyTransactionStore::new(Arc::new(denied), backend)
            .await
            .unwrap();
        assert_eq!(
            denied
                .consume_authenticated(&created.id, &[7; 32])
                .await
                .err(),
            Some(StoreError::Unavailable)
        );
        let (left, expiry, bytes) = a.read_authenticated(&created.id, &[7; 32]).await.unwrap();
        let (right, other_expiry, other_bytes) =
            b.read_authenticated(&created.id, &[7; 32]).await.unwrap();
        assert!(bytes == other_bytes && expiry == other_expiry);
        let (left, right) = tokio::join!(
            a.call(
                Operation::ConsumeAuthenticated,
                &created.id,
                expiry,
                &bytes,
                Some((left.expires_at_ms(), &[]))
            ),
            b.call(
                Operation::ConsumeAuthenticated,
                &created.id,
                other_expiry,
                &other_bytes,
                Some((right.expires_at_ms(), &[]))
            )
        );
        let replies = [left.unwrap(), right.unwrap()];
        assert_eq!(
            replies
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"ok"))
                .count(),
            1
        );
        assert_eq!(
            replies
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"missing"))
                .count(),
            1
        );
        let next = a.create(request(&cfg), [7; 32]).await.unwrap();
        let _: usize = command(&a, redis::cmd("DEL").arg(&a.keys(&next.id))).await;
        // Further corruption cases use a longer freshness window, not an extended existing record.
        let (mut cfg, _, identity) = super::super::context::tests::fixture().await;
        cfg.max_authorization_transactions = 2;
        let cfg = Arc::new(cfg);
        let a = ValkeyTransactionStore::new(cfg.clone(), backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let witness = a.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let context = AuthenticatedAuthorization::new_bound(
            witness,
            identity,
            &[7; 32],
            &cfg,
            seconds * 1000 + micros / 1000,
        )
        .unwrap();
        a.promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let (_, expiry, bytes) = a.read_authenticated(&created.id, &[7; 32]).await.unwrap();
        let copied = a.create(request(&cfg), [7; 32]).await.unwrap();
        let copied_keys = a.keys(&copied.id);
        let _: usize = command(
            &a,
            redis::cmd("HSET")
                .arg(&copied_keys[1])
                .arg("kind")
                .arg("authenticated")
                .arg("expiry")
                .arg(expiry)
                .arg("payload")
                .arg(&bytes),
        )
        .await;
        let _: usize = command(
            &a,
            redis::cmd("ZADD")
                .arg(&copied_keys[0])
                .arg(expiry)
                .arg(&copied_keys[1]),
        )
        .await;
        assert_eq!(
            a.consume_authenticated(&copied.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let keys = a.keys(&created.id);
        for (field, value) in [
            ("payload", vec![b'x'; MAX_AUTHENTICATED_CONTEXT_BYTES + 1]),
            ("kind", b"invalid-kind".to_vec()),
        ] {
            let _: usize =
                command(&a, redis::cmd("HSET").arg(&keys[1]).arg(field).arg(value)).await;
            assert_eq!(
                a.consume_authenticated(&created.id, &[7; 32]).await.err(),
                Some(StoreError::Unavailable)
            );
        }
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys).arg(&copied_keys[1])).await;
    }

    #[tokio::test]
    #[ignore = "requires Docker; creates and removes its own isolated Valkey container"]
    async fn disposable_oauth_valkey_transactions() {
        let password = uuid::Uuid::new_v4().simple().to_string();
        let container = Container(docker(&[
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::6379",
            "valkey/valkey:8",
            "sleep",
            "infinity",
        ]));
        let mut configure = Command::new("docker")
            .args([
                "exec",
                "-i",
                &container.0,
                "sh",
                "-c",
                "umask 077; cat > /tmp/fixture.conf",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        write!(
            configure.stdin.take().unwrap(),
            "requirepass {password}\nsave \"\"\nappendonly no\n"
        )
        .unwrap();
        assert!(
            configure.wait().unwrap().success(),
            "disposable Valkey configuration failed"
        );
        docker(&[
            "exec",
            "-d",
            &container.0,
            "valkey-server",
            "/tmp/fixture.conf",
        ]);
        let backend = BrowserBackendConfig::Valkey {
            url: format!("redis://{}/0", docker(&["port", &container.0, "6379/tcp"])),
            key_prefix: format!("authotron:test:{}", uuid::Uuid::new_v4().simple()),
            password,
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        };
        let cfg = config();
        let mut ready = None;
        for _ in 0..100 {
            if let Ok(store) = ValkeyTransactionStore::new(cfg.clone(), &backend).await {
                ready = Some(store);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let a = ready.expect("disposable Valkey did not become ready");
        let b = ValkeyTransactionStore::new(cfg.clone(), &backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        assert_eq!(
            b.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            b.consume(&created.id, &[8; 32]).await.err(),
            Some(StoreError::Missing)
        );
        let ttl1: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            b.lookup(&created.id, &[7; 32])
                .await
                .unwrap()
                .expires_at_ms(),
            created.expires_at_ms
        );
        let ttl2: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        let witness = b.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        assert_eq!(witness.transaction().expires_at_ms(), created.expires_at_ms);
        assert!(ttl2 < ttl1 && ttl2 > 0);
        let (left, right) = tokio::join!(
            a.consume(&created.id, &[7; 32]),
            b.consume(&created.id, &[7; 32])
        );
        assert_ne!(left.is_ok(), right.is_ok());
        assert!(matches!(
            left.err().or(right.err()),
            Some(StoreError::Missing)
        ));
        let staged = a.create(request(&cfg), [7; 32]).await.unwrap();
        let (left_record, left_bytes, _) = a.read(&staged.id, &[7; 32]).await.unwrap();
        let (right_record, right_bytes, _) = b.read(&staged.id, &[7; 32]).await.unwrap();
        assert!(left_bytes == right_bytes);
        assert_eq!(left_record.expires_at_ms(), right_record.expires_at_ms());
        let (left, right) = tokio::join!(
            a.call(
                Operation::Consume,
                &staged.id,
                left_record.expires_at_ms(),
                &left_bytes,
                None
            ),
            b.call(
                Operation::Consume,
                &staged.id,
                right_record.expires_at_ms(),
                &right_bytes,
                None
            )
        );
        let statuses = [left.unwrap(), right.unwrap()];
        assert_eq!(
            statuses
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"ok"))
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|reply| matches!(reply.as_slice(), [status] if status == b"missing"))
                .count(),
            1
        );
        assert_eq!(
            b.lookup(&staged.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let expiry = seconds * 1000 + micros / 1000 + 1000;
        let short = TransactionId::generate().unwrap();
        let bytes = AuthorizationTransaction::new(request(&cfg), [7; 32], expiry)
            .unwrap()
            .encode()
            .unwrap();
        let reply = a
            .call(Operation::Create, &short, expiry, &bytes, None)
            .await
            .unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"ok"));
        let (_, expected, _) = b.read(&short, &[7; 32]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let reply = a
            .call(Operation::Consume, &short, expiry, &expected, None)
            .await
            .unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"missing"));
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        let mut revoked = (*cfg).clone();
        revoked.clients[0].resources.clear();
        let revoked = ValkeyTransactionStore::new(Arc::new(revoked), &backend)
            .await
            .unwrap();
        assert_eq!(
            revoked.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        assert!(b.lookup(&created.id, &[7; 32]).await.is_ok());
        let (record, expected, _) = a.read(&created.id, &[7; 32]).await.unwrap();
        let _: usize = command(
            &a,
            redis::cmd("HSET")
                .arg(&keys[1])
                .arg("payload")
                .arg("corrupt"),
        )
        .await;
        let reply = a
            .call(
                Operation::Consume,
                &created.id,
                record.expires_at_ms(),
                &expected,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"missing"));
        assert_eq!(
            b.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(
            &a,
            redis::cmd("HSET")
                .arg(&keys[1])
                .arg("payload")
                .arg(vec![b'x'; MAX_TRANSACTION_BYTES + 1]),
        )
        .await;
        assert_eq!(
            b.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys[1])).await;
        let _: usize = command(&a, redis::cmd("RPUSH").arg(&keys[1]).arg("wrong-type")).await;
        assert_eq!(
            b.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys)).await;
        let _: String = command(&a, redis::cmd("SET").arg(&keys[0]).arg("wrong-type")).await;
        assert_eq!(
            a.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 1);
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys[0])).await;
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "-zadd"])).await;
        assert_eq!(
            a.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 0);
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "+zadd"])).await;
        consent_cases(&backend).await;
        effective_deadline_and_hash_shape_cases(&backend).await;
        authenticated_cases(&backend).await;
        code_cases(&backend).await;
        redemption_cases(&backend).await;
        docker(&["stop", &container.0]);
        let code = AuthorizationCode::generate().unwrap();
        assert_eq!(
            b.redeem_code(
                &code,
                "desktop",
                "https://app.example.org/cb",
                "https://mcp.example.org/mcp",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            )
            .await
            .err(),
            Some(CodeStoreError::Unavailable)
        );
        assert_eq!(
            b.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
    }
}
