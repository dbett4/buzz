//! Versioned, transport-neutral authorization context.
//!
//! Authentication adapters produce this context after verifying Nostr proof.
//! Federated identity is optional, but when present it remains distinct from
//! the Nostr authority that signed the request. Raw assertions and mutable
//! display claims never enter this type.

use std::fmt;

use buzz_core::{tenant::TenantContext, CommunityId};
use nostr::PublicKey;
use thiserror::Error;
use uuid::Uuid;

use crate::Scope;

/// Version of the authorization-context contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthContextVersion {
    /// Initial shared authorization-context contract.
    V1,
}

/// Cryptographic proof used to authenticate the Nostr actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// NIP-42 challenge/response over WebSocket.
    Nip42,
    /// NIP-98 signed HTTP request.
    Nip98,
    /// Blossom upload authorization.
    Blossom,
}

/// Entry point that produced the authorization context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTransport {
    /// Relay WebSocket protocol.
    RelayWebSocket,
    /// HTTP relay bridge.
    HttpBridge,
    /// Git-over-HTTP endpoint.
    Git,
    /// Media upload or download endpoint.
    Media,
    /// Huddle audio WebSocket.
    Audio,
}

/// Transport profile used to deliver a federated assertion.
///
/// This records how the assertion reached its verifier. It is intentionally
/// independent of [`AuthTransport`]; each authentication adapter must verify
/// the delivery profile before constructing authorization evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionTransport {
    /// A trusted proxy stripped inbound copies and injected the assertion.
    TrustedProxy,
    /// The client attached the assertion to the authorized request.
    ClientAttached,
}

/// Policy used when no active binding exists for either principal or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentMode {
    /// First use requires an assertion that attests the proven Nostr key.
    AttestedKey,
    /// Bindings must be created by an out-of-band administrative process.
    Provisioned,
    /// First use may bind the proven key without an asserted key claim.
    Tofu,
}

/// Federated-identity requirement resolved for one authorization domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedIdentityRequirement {
    /// Federated identity is not required for this domain.
    NotRequired,
    /// Federated identity is required under the supplied enrollment policy.
    Required(EnrollmentMode),
}

/// Server-resolved federated-identity policy for an authorization decision.
///
/// Raw request data cannot construct this value. A policy adapter must resolve
/// the authorization domain's configuration before producing it. The evidence
/// is intentionally move-only and has no default or deserialization path.
#[derive(PartialEq, Eq)]
pub struct ResolvedFederatedPolicy {
    authorization_domain: CommunityId,
    requirement: FederatedIdentityRequirement,
}

impl fmt::Debug for ResolvedFederatedPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedFederatedPolicy")
            .field("authorization_domain", &"[redacted]")
            .field("requirement", &self.requirement)
            .finish()
    }
}

impl ResolvedFederatedPolicy {
    #[cfg(test)]
    pub(crate) const fn not_required(authorization_domain: CommunityId) -> Self {
        Self {
            authorization_domain,
            requirement: FederatedIdentityRequirement::NotRequired,
        }
    }

    #[cfg(test)]
    pub(crate) const fn required(
        authorization_domain: CommunityId,
        enrollment_mode: EnrollmentMode,
    ) -> Self {
        Self {
            authorization_domain,
            requirement: FederatedIdentityRequirement::Required(enrollment_mode),
        }
    }

    /// Authorization domain whose configuration was resolved.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Resolved federated-identity requirement.
    pub const fn requirement(&self) -> FederatedIdentityRequirement {
        self.requirement
    }
}

/// Provenance recorded when a binding is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingSource {
    /// The identity provider attested the proven Nostr key.
    AttestedKey,
    /// An operator provisioned the binding out of band.
    Provisioned,
    /// The binding was established by trust on first use.
    Tofu,
}

/// Expiry of a validated federated assertion, expressed as Unix seconds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssertionExpiry(u64);

impl fmt::Debug for AssertionExpiry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AssertionExpiry")
            .field(&"[redacted]")
            .finish()
    }
}

impl AssertionExpiry {
    /// Build a non-zero assertion expiry.
    pub const fn new(unix_seconds: u64) -> Result<Self, AuthContextError> {
        if unix_seconds == 0 {
            return Err(AuthContextError::InvalidAssertionExpiry);
        }
        Ok(Self(unix_seconds))
    }

    /// Expiry as seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    /// Returns `true` when the assertion is no longer valid at `now`.
    pub const fn is_expired_at(self, now_unix_seconds: u64) -> bool {
        self.0 <= now_unix_seconds
    }
}

/// Earliest valid time from a validated federated assertion, as Unix seconds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssertionNotBefore(u64);

impl fmt::Debug for AssertionNotBefore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AssertionNotBefore")
            .field(&"[redacted]")
            .finish()
    }
}

impl AssertionNotBefore {
    /// Preserve a validated `nbf` timestamp for finalization checks.
    pub const fn new(unix_seconds: u64) -> Self {
        Self(unix_seconds)
    }

    /// Earliest valid time as seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    /// Returns `true` while the assertion is not yet valid at `now`.
    pub const fn is_not_yet_valid_at(self, now_unix_seconds: u64) -> bool {
        self.0 > now_unix_seconds
    }
}

/// Expiry imposed by a separately verified delegation proof.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DelegationExpiry(u64);

impl fmt::Debug for DelegationExpiry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DelegationExpiry")
            .field(&"[redacted]")
            .finish()
    }
}

impl DelegationExpiry {
    /// Build a non-zero delegation expiry.
    pub const fn new(unix_seconds: u64) -> Result<Self, AuthContextError> {
        if unix_seconds == 0 {
            return Err(AuthContextError::InvalidDelegationExpiry);
        }
        Ok(Self(unix_seconds))
    }

    /// Expiry as seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    /// Returns `true` when the delegation is no longer valid at `now`.
    pub const fn is_expired_at(self, now_unix_seconds: u64) -> bool {
        self.0 <= now_unix_seconds
    }
}

/// Server-verified Nostr authority for a request or connection.
#[derive(PartialEq, Eq)]
pub struct NostrAuthority {
    actor_pubkey: PublicKey,
    proof_method: AuthMethod,
    verified_delegation: Option<VerifiedTransportDelegation>,
}

impl fmt::Debug for NostrAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NostrAuthority")
            .field("actor_pubkey", &"[redacted]")
            .field("proof_method", &self.proof_method)
            .field(
                "verified_delegation",
                &self.verified_delegation.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl NostrAuthority {
    fn new(proof: VerifiedNostrProof) -> Self {
        Self {
            actor_pubkey: proof.actor_pubkey,
            proof_method: proof.proof_method,
            verified_delegation: proof.verified_delegation,
        }
    }

    /// Authenticated Nostr actor.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Proof method used to authenticate the actor.
    pub const fn proof_method(&self) -> AuthMethod {
        self.proof_method
    }

    /// Cryptographically verified owner for a delegated Nostr actor.
    pub const fn verified_owner_pubkey(&self) -> Option<PublicKey> {
        match &self.verified_delegation {
            Some(delegation) => Some(delegation.owner_pubkey()),
            None => None,
        }
    }

    /// Cryptographically verified owner-to-actor delegation, when present.
    pub const fn verified_delegation(&self) -> Option<&VerifiedTransportDelegation> {
        self.verified_delegation.as_ref()
    }
}

/// Stable identity-provider principal.
///
/// Equality uses the exact validated issuer and subject values. Neither value
/// is suitable for public events or general-purpose logs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FederatedPrincipal {
    issuer: String,
    subject: String,
}

impl FederatedPrincipal {
    /// Build an issuer-qualified principal from validated assertion claims.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, AuthContextError> {
        let issuer = issuer.into();
        let subject = subject.into();
        if issuer.trim().is_empty() {
            return Err(AuthContextError::EmptyIssuer);
        }
        if subject.trim().is_empty() {
            return Err(AuthContextError::EmptySubject);
        }
        Ok(Self { issuer, subject })
    }

    /// Validated identity-provider issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Stable, non-reassignable subject within the issuer namespace.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl fmt::Debug for FederatedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederatedPrincipal")
            .field("issuer", &"[redacted]")
            .field("subject", &"[redacted]")
            .finish()
    }
}

/// Federated assertion accepted by the configured assertion verifier.
///
/// The verifier must enforce an allowed algorithm and key, require correctly
/// typed `exp`, `iss`, and `aud` claims, validate the issuer and audience, and
/// reject a malformed `nbf` before constructing this evidence. Finalization
/// independently enforces the preserved `nbf` against server time. Raw
/// assertion claims cannot construct it from outside `buzz-auth`. Private
/// identity attributes and public display labels are deliberately excluded.
/// The evidence is intentionally move-only and has no default or
/// deserialization path.
#[derive(PartialEq, Eq)]
pub struct VerifiedFederatedAssertion {
    authorization_domain: CommunityId,
    authorized_transport: AuthTransport,
    principal: FederatedPrincipal,
    transport: AssertionTransport,
    not_before: Option<AssertionNotBefore>,
    expires_at: AssertionExpiry,
}

impl VerifiedFederatedAssertion {
    #[cfg(test)]
    pub(crate) const fn new(
        authorization_domain: CommunityId,
        authorized_transport: AuthTransport,
        principal: FederatedPrincipal,
        transport: AssertionTransport,
        not_before: Option<AssertionNotBefore>,
        expires_at: AssertionExpiry,
    ) -> Self {
        Self {
            authorization_domain,
            authorized_transport,
            principal,
            transport,
            not_before,
            expires_at,
        }
    }

    /// Authorization domain for which the assertion was verified.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Transport whose request or connection the verifier authorized.
    pub const fn authorized_transport(&self) -> AuthTransport {
        self.authorized_transport
    }

    /// Issuer-qualified principal from the verified assertion.
    pub const fn principal(&self) -> &FederatedPrincipal {
        &self.principal
    }

    /// Verified assertion delivery profile.
    pub const fn transport(&self) -> AssertionTransport {
        self.transport
    }

    /// Earliest valid time preserved from the verified assertion, when present.
    pub const fn not_before(&self) -> Option<AssertionNotBefore> {
        self.not_before
    }

    /// Upper time bound carried by the verified assertion.
    pub const fn expires_at(&self) -> AssertionExpiry {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedFederatedAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedFederatedAssertion")
            .field("authorization_domain", &"[redacted]")
            .field("authorized_transport", &self.authorized_transport)
            .field("principal", &self.principal)
            .field("transport", &self.transport)
            .field("not_before", &self.not_before.map(|_| "[redacted]"))
            .field("expires_at", &"[redacted]")
            .finish()
    }
}

/// Monotonically increasing version of an identity-to-key binding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BindingVersion(u64);

impl fmt::Debug for BindingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BindingVersion")
            .field(&"[redacted]")
            .finish()
    }
}

impl BindingVersion {
    /// Initial version assigned to a newly created binding.
    pub const INITIAL: Self = Self(1);

    /// Build a non-zero binding version.
    pub const fn new(value: u64) -> Result<Self, AuthContextError> {
        if value == 0 {
            return Err(AuthContextError::InvalidBindingVersion);
        }
        Ok(Self(value))
    }

    /// Numeric binding version.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable reference to one active identity-to-key binding.
///
/// This reference is identity evidence. It is not an authorization lease and
/// does not by itself provide expiry or live-revocation enforcement. An
/// authoritative binding adapter constructs this move-only value after checking
/// active lifecycle state; it has no default or deserialization path.
#[derive(PartialEq, Eq)]
pub struct VersionedBindingRef {
    authorization_domain: CommunityId,
    binding_id: Uuid,
    principal: FederatedPrincipal,
    bound_pubkey: PublicKey,
    binding_version: BindingVersion,
    source: BindingSource,
}

impl fmt::Debug for VersionedBindingRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedBindingRef")
            .field("authorization_domain", &"[redacted]")
            .field("binding_id", &"[redacted]")
            .field("principal", &self.principal)
            .field("bound_pubkey", &"[redacted]")
            .field("binding_version", &"[redacted]")
            .field("source", &self.source)
            .finish()
    }
}

impl VersionedBindingRef {
    /// Build a reference to an active, versioned binding.
    #[cfg(test)]
    pub(crate) fn new(
        authorization_domain: CommunityId,
        binding_id: Uuid,
        principal: FederatedPrincipal,
        bound_pubkey: PublicKey,
        binding_version: BindingVersion,
        source: BindingSource,
    ) -> Result<Self, AuthContextError> {
        if binding_id.is_nil() {
            return Err(AuthContextError::InvalidBindingId);
        }
        Ok(Self {
            authorization_domain,
            binding_id,
            principal,
            bound_pubkey,
            binding_version,
            source,
        })
    }

    /// Server-resolved authorization domain that owns the binding.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Stable binding identifier.
    pub const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    /// Issuer-qualified principal represented by the binding.
    pub const fn principal(&self) -> &FederatedPrincipal {
        &self.principal
    }

    /// Nostr key owned by the binding.
    pub const fn bound_pubkey(&self) -> PublicKey {
        self.bound_pubkey
    }

    /// Current binding version.
    pub const fn binding_version(&self) -> BindingVersion {
        self.binding_version
    }

    /// Provenance of the active binding.
    pub const fn source(&self) -> BindingSource {
        self.source
    }
}

/// Capability represented by a verified owner-to-delegate proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationCapability {
    /// Authorizes the complete request or connection represented by the context.
    TransportWide,
}

/// Transport-wide delegation from a bound owner to the authenticated key.
///
/// A verifier may construct this only after proving the capability authorizes
/// the complete target request or connection. Time-only constraints may be
/// reduced to [`DelegationExpiry`], but operation-, event-kind-, or
/// request-specific constraints must not be discarded or promoted into this
/// transport-wide evidence. This move-only evidence has no default or
/// deserialization path.
#[derive(PartialEq, Eq)]
pub struct VerifiedTransportDelegation {
    owner_pubkey: PublicKey,
    delegate_pubkey: PublicKey,
    capability: DelegationCapability,
    expires_at: Option<DelegationExpiry>,
}

impl fmt::Debug for VerifiedTransportDelegation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTransportDelegation")
            .field("owner_pubkey", &"[redacted]")
            .field("delegate_pubkey", &"[redacted]")
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at.map(|_| "[redacted]"))
            .finish()
    }
}

impl VerifiedTransportDelegation {
    /// Build transport-wide evidence after validating both keys and confirming
    /// that no narrower capability constraint is being discarded.
    #[cfg(test)]
    pub(crate) fn new_unrestricted(
        owner_pubkey: PublicKey,
        delegate_pubkey: PublicKey,
        expires_at: Option<DelegationExpiry>,
    ) -> Result<Self, AuthContextError> {
        if owner_pubkey == delegate_pubkey {
            return Err(AuthContextError::SelfDelegation);
        }
        Ok(Self {
            owner_pubkey,
            delegate_pubkey,
            capability: DelegationCapability::TransportWide,
            expires_at,
        })
    }

    /// Bound owner that authorized the delegate.
    pub const fn owner_pubkey(&self) -> PublicKey {
        self.owner_pubkey
    }

    /// Authenticated delegate key.
    pub const fn delegate_pubkey(&self) -> PublicKey {
        self.delegate_pubkey
    }

    /// Verified capability scope.
    pub const fn capability(&self) -> DelegationCapability {
        self.capability
    }

    /// Optional upper bound imposed by the delegation proof.
    pub const fn expires_at(&self) -> Option<DelegationExpiry> {
        self.expires_at
    }
}

/// Cryptographically verified Nostr proof for one request or connection.
///
/// Transport verifiers inside `buzz-auth` produce this evidence after checking
/// the signature and transport-specific binding. Raw request keys and claimed
/// proof methods cannot construct it in relay call sites. Conditional
/// delegation may be attached only when it has been fully evaluated for the
/// target operation or safely reduced to transport-wide evidence. The evidence
/// is intentionally move-only and has no default or deserialization path.
#[derive(PartialEq, Eq)]
pub struct VerifiedNostrProof {
    authorization_domain: CommunityId,
    authorized_transport: AuthTransport,
    actor_pubkey: PublicKey,
    proof_method: AuthMethod,
    verified_delegation: Option<VerifiedTransportDelegation>,
}

impl VerifiedNostrProof {
    #[cfg(test)]
    pub(crate) fn new(
        authorization_domain: CommunityId,
        authorized_transport: AuthTransport,
        actor_pubkey: PublicKey,
        proof_method: AuthMethod,
        verified_delegation: Option<VerifiedTransportDelegation>,
    ) -> Result<Self, AuthContextError> {
        if !transport_accepts_proof(authorized_transport, proof_method) {
            return Err(AuthContextError::TransportProofMismatch);
        }
        if verified_delegation
            .as_ref()
            .is_some_and(|delegation| delegation.delegate_pubkey() != actor_pubkey)
        {
            return Err(AuthContextError::DelegateKeyMismatch);
        }
        Ok(Self {
            authorization_domain,
            authorized_transport,
            actor_pubkey,
            proof_method,
            verified_delegation,
        })
    }

    /// Authorization domain for which the Nostr proof was verified.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Transport whose request or connection the proof authorized.
    pub const fn authorized_transport(&self) -> AuthTransport {
        self.authorized_transport
    }

    /// Authenticated Nostr actor.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Cryptographic proof method accepted by the verifier.
    pub const fn proof_method(&self) -> AuthMethod {
        self.proof_method
    }

    /// Verified owner-to-actor delegation, when present.
    pub const fn verified_delegation(&self) -> Option<&VerifiedTransportDelegation> {
        self.verified_delegation.as_ref()
    }
}

impl fmt::Debug for VerifiedNostrProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedNostrProof")
            .field("authorization_domain", &"[redacted]")
            .field("authorized_transport", &self.authorized_transport)
            .field("actor_pubkey", &"[redacted]")
            .field("proof_method", &self.proof_method)
            .field(
                "verified_delegation",
                &self.verified_delegation.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Stable reason for an allowed authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationReason {
    /// Only the configured Nostr proof was required.
    NostrOnly,
    /// An existing direct federated binding matched.
    ///
    /// Enrollment policy governs creation of new bindings. Resolution of an
    /// existing active binding, including future lease checks, is a separate
    /// lifecycle decision.
    ExistingBinding,
    /// A direct binding was created under attested-key enrollment.
    EnrolledAttestedKey,
    /// A direct binding was created under trust-on-first-use enrollment.
    EnrolledTofu,
    /// A verified delegate derived authority from a bound owner.
    DelegatedOwnerBinding,
}

impl AuthorizationReason {
    /// Stable audit and metric code for this decision.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NostrOnly => "nostr_only",
            Self::ExistingBinding => "federated_binding_existing",
            Self::EnrolledAttestedKey => "federated_binding_enrolled_attested_key",
            Self::EnrolledTofu => "federated_binding_enrolled_tofu",
            Self::DelegatedOwnerBinding => "federated_delegated_owner_binding",
        }
    }
}

/// Federated authorization attached to a Nostr-authenticated actor.
#[derive(PartialEq, Eq)]
pub enum FederatedAuthorization {
    /// This deployment does not require federated identity.
    ///
    /// An independently verified Nostr owner may still be present in the
    /// [`NostrAuthority`] without acquiring a federated binding.
    NotRequired,
    /// The actor directly owns the active federated binding.
    Direct {
        /// Active identity-to-key binding.
        binding: VersionedBindingRef,
        /// Current assertion accepted by the configured verifier.
        assertion: VerifiedFederatedAssertion,
        /// Stable reason describing whether the binding existed or was enrolled.
        reason: AuthorizationReason,
    },
    /// The actor is delegated by the owner of an active federated binding.
    Delegated {
        /// Owner's active binding.
        owner: VersionedBindingRef,
        /// Current owner assertion accepted by the configured verifier.
        assertion: VerifiedFederatedAssertion,
    },
}

impl fmt::Debug for FederatedAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequired => formatter.write_str("NotRequired"),
            Self::Direct {
                binding,
                assertion,
                reason,
                ..
            } => formatter
                .debug_struct("Direct")
                .field("binding", binding)
                .field("assertion", assertion)
                .field("reason", reason)
                .finish(),
            Self::Delegated { owner, assertion } => formatter
                .debug_struct("Delegated")
                .field("owner", owner)
                .field("assertion", assertion)
                .finish(),
        }
    }
}

/// Successful community admission and permissions for one decision.
///
/// An authorization adapter may construct this value only after membership,
/// invite, moderation, or equivalent community policy has allowed the actor.
/// Durable identity enrollment and public assertion publication must not occur
/// before this evidence exists; future binding adapters should require a borrow
/// of it before committing either side effect. Raw request scopes and channel
/// identifiers cannot construct this value in relay call sites. The resolution
/// is intentionally move-only and has no default or deserialization path.
#[derive(PartialEq, Eq)]
pub struct AuthorizedCommunityAccess {
    authorization_domain: CommunityId,
    scopes: Vec<Scope>,
    channel_ids: Option<Vec<Uuid>>,
}

impl AuthorizedCommunityAccess {
    #[cfg(test)]
    pub(crate) const fn new(
        authorization_domain: CommunityId,
        scopes: Vec<Scope>,
        channel_ids: Option<Vec<Uuid>>,
    ) -> Self {
        Self {
            authorization_domain,
            scopes,
            channel_ids,
        }
    }

    /// Authorization domain for which the permissions were resolved.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Permission scopes resolved for the decision.
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Optional channel restriction resolved for the decision.
    pub fn channel_ids(&self) -> Option<&[Uuid]> {
        self.channel_ids.as_deref()
    }
}

impl fmt::Debug for AuthorizedCommunityAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedCommunityAccess")
            .field("authorization_domain", &"[redacted]")
            .field("scopes", &"[redacted]")
            .field("channel_ids", &"[redacted]")
            .finish()
    }
}

/// Initial shared authorization-context contract.
#[derive(PartialEq, Eq)]
pub struct AuthContextV1 {
    tenant: TenantContext,
    correlation_id: Uuid,
    transport: AuthTransport,
    nostr: NostrAuthority,
    federated_policy: ResolvedFederatedPolicy,
    federated: FederatedAuthorization,
    scopes: Vec<Scope>,
    channel_ids: Option<Vec<Uuid>>,
}

/// Server-verified inputs consumed by the V1 authorization finalizer.
#[derive(PartialEq, Eq)]
pub struct AuthContextInput {
    tenant: TenantContext,
    correlation_id: Uuid,
    nostr_proof: VerifiedNostrProof,
    community_access: AuthorizedCommunityAccess,
}

impl AuthContextInput {
    /// Collect evidence after cryptographic authentication and community
    /// admission have both succeeded.
    pub fn new(
        tenant: TenantContext,
        correlation_id: Uuid,
        nostr_proof: VerifiedNostrProof,
        community_access: AuthorizedCommunityAccess,
    ) -> Self {
        Self {
            tenant,
            correlation_id,
            nostr_proof,
            community_access,
        }
    }
}

impl fmt::Debug for AuthContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthContextV1")
            .field("authorization_domain", &"[redacted]")
            .field("correlation_id", &"[redacted]")
            .field("transport", &self.transport)
            .field("nostr", &self.nostr)
            .field("federated_policy", &self.federated_policy)
            .field("federated", &self.federated)
            .field("scopes", &"[redacted]")
            .field("channel_ids", &"[redacted]")
            .finish()
    }
}

/// Versioned result of successful request or connection authorization.
///
/// This security-boundary type intentionally has no default or deserialization
/// path. Persisted or transported data must be re-verified and finalized rather
/// than decoded directly into an authorized context.
#[derive(PartialEq, Eq)]
pub enum AuthContext {
    /// Initial shared authorization-context contract.
    V1(AuthContextV1),
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1(context) => formatter.debug_tuple("V1").field(context).finish(),
        }
    }
}

impl AuthContext {
    /// Validate all authorization evidence and finalize an immutable V1 context.
    ///
    /// Adapters must preserve this phase order: cryptographic proof and
    /// read-only assertion validation; community admission and capability
    /// resolution; atomic binding/enrollment; then finalization. A denial before
    /// admission must not create or refresh a binding, claim membership, or
    /// publish a public identity assertion.
    ///
    /// `now_unix_seconds` must come from the server clock for the authorization
    /// decision being finalized.
    pub fn finalize_v1(
        input: AuthContextInput,
        federated_policy: ResolvedFederatedPolicy,
        authorization: FederatedAuthorization,
        now_unix_seconds: u64,
    ) -> Result<Self, AuthContextError> {
        let authorization_domain = input.tenant.community();
        let transport = input.nostr_proof.authorized_transport();
        if input.nostr_proof.authorization_domain() != authorization_domain {
            return Err(AuthContextError::NostrProofDomainMismatch);
        }
        if federated_policy.authorization_domain() != authorization_domain {
            return Err(AuthContextError::PolicyDomainMismatch);
        }
        if input.community_access.authorization_domain() != authorization_domain {
            return Err(AuthContextError::CommunityAccessDomainMismatch);
        }
        if !transport_accepts_proof(transport, input.nostr_proof.proof_method()) {
            return Err(AuthContextError::TransportProofMismatch);
        }
        validate_federated_authorization(
            authorization_domain,
            transport,
            &input.nostr_proof,
            &federated_policy,
            &authorization,
            now_unix_seconds,
        )?;
        let nostr = NostrAuthority::new(input.nostr_proof);
        Ok(Self::V1(AuthContextV1 {
            tenant: input.tenant,
            correlation_id: input.correlation_id,
            transport,
            nostr,
            federated_policy,
            federated: authorization,
            scopes: input.community_access.scopes,
            channel_ids: input.community_access.channel_ids,
        }))
    }

    /// Contract version represented by this context.
    pub const fn version(&self) -> AuthContextVersion {
        match self {
            Self::V1(_) => AuthContextVersion::V1,
        }
    }

    /// Server-resolved tenant for the request or connection.
    pub const fn tenant(&self) -> &TenantContext {
        match self {
            Self::V1(context) => &context.tenant,
        }
    }

    /// Request or connection correlation identifier.
    pub const fn correlation_id(&self) -> Uuid {
        match self {
            Self::V1(context) => context.correlation_id,
        }
    }

    /// Transport that established this authorization context.
    pub const fn transport(&self) -> AuthTransport {
        match self {
            Self::V1(context) => context.transport,
        }
    }

    /// Verified Nostr authority.
    pub const fn nostr(&self) -> &NostrAuthority {
        match self {
            Self::V1(context) => &context.nostr,
        }
    }

    /// Authenticated Nostr actor.
    pub const fn pubkey(&self) -> PublicKey {
        self.nostr().actor_pubkey()
    }

    /// Proof method used to authenticate the Nostr actor.
    pub const fn auth_method(&self) -> AuthMethod {
        self.nostr().proof_method()
    }

    /// Cryptographically verified owner for a delegated Nostr actor.
    pub const fn agent_owner_pubkey(&self) -> Option<PublicKey> {
        self.nostr().verified_owner_pubkey()
    }

    /// Federated authorization associated with the Nostr actor.
    pub const fn federated_authorization(&self) -> &FederatedAuthorization {
        match self {
            Self::V1(context) => &context.federated,
        }
    }

    /// Federated-identity policy resolved for this authorization decision.
    pub const fn federated_policy(&self) -> &ResolvedFederatedPolicy {
        match self {
            Self::V1(context) => &context.federated_policy,
        }
    }

    /// Stable reason for the successful authorization decision.
    pub const fn authorization_reason(&self) -> AuthorizationReason {
        match self.federated_authorization() {
            FederatedAuthorization::NotRequired => AuthorizationReason::NostrOnly,
            FederatedAuthorization::Direct { reason, .. } => *reason,
            FederatedAuthorization::Delegated { .. } => AuthorizationReason::DelegatedOwnerBinding,
        }
    }

    /// Permission scopes granted to the context.
    pub fn scopes(&self) -> &[Scope] {
        match self {
            Self::V1(context) => &context.scopes,
        }
    }

    /// Optional channel restriction.
    pub fn channel_ids(&self) -> Option<&[Uuid]> {
        match self {
            Self::V1(context) => context.channel_ids.as_deref(),
        }
    }

    /// Returns `true` if this context includes the given scope.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes().contains(scope)
    }
}

const fn transport_accepts_proof(transport: AuthTransport, proof_method: AuthMethod) -> bool {
    match transport {
        AuthTransport::RelayWebSocket | AuthTransport::Audio => {
            matches!(proof_method, AuthMethod::Nip42)
        }
        AuthTransport::HttpBridge | AuthTransport::Git => matches!(proof_method, AuthMethod::Nip98),
        AuthTransport::Media => matches!(proof_method, AuthMethod::Nip98 | AuthMethod::Blossom),
    }
}

fn validate_federated_authorization(
    authorization_domain: CommunityId,
    authorized_transport: AuthTransport,
    nostr_proof: &VerifiedNostrProof,
    federated_policy: &ResolvedFederatedPolicy,
    authorization: &FederatedAuthorization,
    now_unix_seconds: u64,
) -> Result<(), AuthContextError> {
    match (federated_policy.requirement(), authorization) {
        (FederatedIdentityRequirement::Required(_), FederatedAuthorization::NotRequired) => {
            return Err(AuthContextError::FederatedIdentityRequired);
        }
        (FederatedIdentityRequirement::NotRequired, FederatedAuthorization::NotRequired) => {}
        (FederatedIdentityRequirement::NotRequired, _) => {
            return Err(AuthContextError::UnexpectedFederatedAuthorization);
        }
        (FederatedIdentityRequirement::Required(_), _) => {}
    }

    let actor_pubkey = nostr_proof.actor_pubkey();
    let verified_delegation = nostr_proof.verified_delegation();
    match authorization {
        FederatedAuthorization::NotRequired => {}
        FederatedAuthorization::Direct {
            binding,
            assertion,
            reason,
        } => {
            if binding.authorization_domain() != authorization_domain {
                return Err(AuthContextError::BindingDomainMismatch);
            }
            if assertion.authorization_domain() != authorization_domain {
                return Err(AuthContextError::AssertionDomainMismatch);
            }
            if assertion.authorized_transport() != authorized_transport {
                return Err(AuthContextError::AssertionTransportMismatch);
            }
            if assertion.principal() != binding.principal() {
                return Err(AuthContextError::AssertionPrincipalMismatch);
            }
            if verified_delegation.is_some() {
                return Err(AuthContextError::DirectAuthorizationHasOwner);
            }
            if binding.bound_pubkey() != actor_pubkey {
                return Err(AuthContextError::DirectBindingKeyMismatch);
            }
            validate_assertion_time(assertion, now_unix_seconds)?;
            let FederatedIdentityRequirement::Required(enrollment_mode) =
                federated_policy.requirement()
            else {
                return Err(AuthContextError::UnexpectedFederatedAuthorization);
            };
            if !direct_reason_is_valid(*reason, enrollment_mode, binding.source()) {
                return Err(AuthContextError::InvalidAuthorizationReason);
            }
        }
        FederatedAuthorization::Delegated { owner, assertion } => {
            if owner.authorization_domain() != authorization_domain {
                return Err(AuthContextError::BindingDomainMismatch);
            }
            if assertion.authorization_domain() != authorization_domain {
                return Err(AuthContextError::AssertionDomainMismatch);
            }
            if assertion.authorized_transport() != authorized_transport {
                return Err(AuthContextError::AssertionTransportMismatch);
            }
            if assertion.principal() != owner.principal() {
                return Err(AuthContextError::AssertionPrincipalMismatch);
            }
            let Some(delegation) = verified_delegation else {
                return Err(AuthContextError::DelegationRequired);
            };
            if delegation.owner_pubkey() != owner.bound_pubkey() {
                return Err(AuthContextError::DelegatedOwnerMismatch);
            }
            validate_assertion_time(assertion, now_unix_seconds)?;
            if delegation
                .expires_at()
                .is_some_and(|expiry| expiry.is_expired_at(now_unix_seconds))
            {
                return Err(AuthContextError::DelegationExpired);
            }
        }
    }
    Ok(())
}

fn validate_assertion_time(
    assertion: &VerifiedFederatedAssertion,
    now_unix_seconds: u64,
) -> Result<(), AuthContextError> {
    if assertion
        .not_before()
        .is_some_and(|not_before| not_before.is_not_yet_valid_at(now_unix_seconds))
    {
        return Err(AuthContextError::AssertionNotYetValid);
    }
    if assertion.expires_at().is_expired_at(now_unix_seconds) {
        return Err(AuthContextError::AssertionExpired);
    }
    Ok(())
}

const fn direct_reason_is_valid(
    reason: AuthorizationReason,
    enrollment_mode: EnrollmentMode,
    binding_source: BindingSource,
) -> bool {
    match reason {
        AuthorizationReason::ExistingBinding => true,
        AuthorizationReason::EnrolledAttestedKey => {
            matches!(enrollment_mode, EnrollmentMode::AttestedKey)
                && matches!(binding_source, BindingSource::AttestedKey)
        }
        AuthorizationReason::EnrolledTofu => {
            matches!(enrollment_mode, EnrollmentMode::Tofu)
                && matches!(
                    binding_source,
                    BindingSource::Tofu | BindingSource::AttestedKey
                )
        }
        AuthorizationReason::NostrOnly | AuthorizationReason::DelegatedOwnerBinding => false,
    }
}

/// Invalid authorization-context construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthContextError {
    /// Issuer was empty.
    #[error("federated principal issuer must not be empty")]
    EmptyIssuer,
    /// Subject was empty.
    #[error("federated principal subject must not be empty")]
    EmptySubject,
    /// Binding version was zero.
    #[error("identity binding version must be greater than zero")]
    InvalidBindingVersion,
    /// Binding identifier was the nil UUID.
    #[error("identity binding identifier must not be nil")]
    InvalidBindingId,
    /// Assertion expiry was not a valid Unix timestamp.
    #[error("federated assertion expiry must be greater than zero")]
    InvalidAssertionExpiry,
    /// Delegation expiry was not a valid Unix timestamp.
    #[error("delegation expiry must be greater than zero")]
    InvalidDelegationExpiry,
    /// Assertion had expired when authorization was evaluated.
    #[error("federated assertion has expired")]
    AssertionExpired,
    /// Assertion was used before its validated not-before bound.
    #[error("federated assertion is not yet valid")]
    AssertionNotYetValid,
    /// Resolved policy required federated identity, but none was supplied.
    #[error("federated identity is required by the resolved authorization policy")]
    FederatedIdentityRequired,
    /// Federated authorization was supplied for a domain that does not use it.
    #[error("federated authorization does not match the resolved authorization policy")]
    UnexpectedFederatedAuthorization,
    /// Delegation had expired when authorization was evaluated.
    #[error("verified delegation has expired")]
    DelegationExpired,
    /// Owner and delegate were the same key.
    #[error("delegation owner and delegate must be different keys")]
    SelfDelegation,
    /// Direct authorization reason did not match its enrollment policy or source.
    #[error("federated authorization reason does not match binding provenance")]
    InvalidAuthorizationReason,
    /// Binding belonged to a different server-resolved authorization domain.
    #[error("federated binding does not belong to the authorization domain")]
    BindingDomainMismatch,
    /// Nostr proof was verified for a different authorization domain.
    #[error("Nostr proof does not belong to the authorization domain")]
    NostrProofDomainMismatch,
    /// Federated policy was resolved for a different authorization domain.
    #[error("federated policy does not belong to the authorization domain")]
    PolicyDomainMismatch,
    /// Community admission was resolved for a different authorization domain.
    #[error("community admission does not belong to the authorization domain")]
    CommunityAccessDomainMismatch,
    /// Assertion was verified for a different authorization domain.
    #[error("federated assertion does not belong to the authorization domain")]
    AssertionDomainMismatch,
    /// Assertion was verified for a different transport.
    #[error("federated assertion does not match the authorization transport")]
    AssertionTransportMismatch,
    /// Validated assertion principal did not match the active binding.
    #[error("federated assertion principal does not match the active binding")]
    AssertionPrincipalMismatch,
    /// Proof method was not valid for the transport being authorized.
    #[error("Nostr proof method does not match authorization transport")]
    TransportProofMismatch,
    /// Direct federated authorization was attached to a delegated Nostr actor.
    #[error("direct federated authorization cannot include a delegated Nostr owner")]
    DirectAuthorizationHasOwner,
    /// Direct binding key did not match the authenticated actor.
    #[error("direct federated binding does not match the authenticated Nostr key")]
    DirectBindingKeyMismatch,
    /// Delegated authorization named a different actor.
    #[error("delegated federated authorization does not match the authenticated Nostr key")]
    DelegateKeyMismatch,
    /// Delegated federated authorization lacked verified Nostr delegation.
    #[error("delegated federated authorization requires verified Nostr delegation")]
    DelegationRequired,
    /// Delegated authorization did not match the verified Nostr owner.
    #[error("delegated federated authorization does not match the verified Nostr owner")]
    DelegatedOwnerMismatch,
}

impl AuthContextError {
    /// Stable audit and metric code for this rejected finalization.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyIssuer => "federated_principal_empty_issuer",
            Self::EmptySubject => "federated_principal_empty_subject",
            Self::InvalidBindingVersion => "federated_binding_invalid_version",
            Self::InvalidBindingId => "federated_binding_invalid_id",
            Self::InvalidAssertionExpiry => "federated_assertion_invalid_expiry",
            Self::InvalidDelegationExpiry => "delegation_invalid_expiry",
            Self::AssertionExpired => "federated_assertion_expired",
            Self::AssertionNotYetValid => "federated_assertion_not_yet_valid",
            Self::FederatedIdentityRequired => "federated_identity_required",
            Self::UnexpectedFederatedAuthorization => "federated_authorization_unexpected",
            Self::DelegationExpired => "delegation_expired",
            Self::SelfDelegation => "delegation_self_reference",
            Self::InvalidAuthorizationReason => "federated_binding_invalid_reason",
            Self::BindingDomainMismatch => "federated_binding_domain_mismatch",
            Self::NostrProofDomainMismatch => "nostr_proof_domain_mismatch",
            Self::PolicyDomainMismatch => "federated_policy_domain_mismatch",
            Self::CommunityAccessDomainMismatch => "community_access_domain_mismatch",
            Self::AssertionDomainMismatch => "federated_assertion_domain_mismatch",
            Self::AssertionTransportMismatch => "federated_assertion_transport_mismatch",
            Self::AssertionPrincipalMismatch => "federated_assertion_principal_mismatch",
            Self::TransportProofMismatch => "nostr_transport_proof_mismatch",
            Self::DirectAuthorizationHasOwner => "federated_direct_has_owner",
            Self::DirectBindingKeyMismatch => "federated_direct_key_mismatch",
            Self::DelegateKeyMismatch => "federated_delegate_key_mismatch",
            Self::DelegationRequired => "federated_delegation_required",
            Self::DelegatedOwnerMismatch => "federated_delegated_owner_mismatch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::CommunityId;
    use nostr::Keys;

    fn tenant(value: u128) -> TenantContext {
        TenantContext::resolved(authorization_domain(value), "relay.example")
    }

    fn authorization_domain(value: u128) -> CommunityId {
        CommunityId::from_uuid(Uuid::from_u128(value))
    }

    fn principal() -> FederatedPrincipal {
        FederatedPrincipal::new("https://idp.example", "subject-123")
            .expect("synthetic principal is valid")
    }

    fn assertion(
        principal: FederatedPrincipal,
        transport: AssertionTransport,
        expiry: u64,
    ) -> VerifiedFederatedAssertion {
        let authorized_transport = match transport {
            AssertionTransport::TrustedProxy => AuthTransport::RelayWebSocket,
            AssertionTransport::ClientAttached => AuthTransport::HttpBridge,
        };
        assertion_in(1, authorized_transport, principal, transport, expiry)
    }

    fn assertion_in(
        domain: u128,
        authorized_transport: AuthTransport,
        principal: FederatedPrincipal,
        transport: AssertionTransport,
        expiry: u64,
    ) -> VerifiedFederatedAssertion {
        assertion_with_bounds_in(
            domain,
            authorized_transport,
            principal,
            transport,
            None,
            expiry,
        )
    }

    fn assertion_with_bounds_in(
        domain: u128,
        authorized_transport: AuthTransport,
        principal: FederatedPrincipal,
        transport: AssertionTransport,
        not_before: Option<u64>,
        expiry: u64,
    ) -> VerifiedFederatedAssertion {
        VerifiedFederatedAssertion::new(
            authorization_domain(domain),
            authorized_transport,
            principal,
            transport,
            not_before.map(AssertionNotBefore::new),
            AssertionExpiry::new(expiry).expect("synthetic assertion expiry is valid"),
        )
    }

    fn policy_not_required() -> ResolvedFederatedPolicy {
        ResolvedFederatedPolicy::not_required(authorization_domain(1))
    }

    fn policy_required(enrollment_mode: EnrollmentMode) -> ResolvedFederatedPolicy {
        ResolvedFederatedPolicy::required(authorization_domain(1), enrollment_mode)
    }

    fn binding(pubkey: PublicKey) -> VersionedBindingRef {
        binding_in(1, pubkey)
    }

    fn binding_in(domain: u128, pubkey: PublicKey) -> VersionedBindingRef {
        VersionedBindingRef::new(
            authorization_domain(domain),
            Uuid::from_u128(10),
            principal(),
            pubkey,
            BindingVersion::INITIAL,
            BindingSource::AttestedKey,
        )
        .expect("synthetic binding identifier is valid")
    }

    fn input(
        actor_pubkey: PublicKey,
        transport: AuthTransport,
        verified_owner_pubkey: Option<PublicKey>,
    ) -> AuthContextInput {
        input_with_delegation_expiry(actor_pubkey, transport, verified_owner_pubkey, 200)
    }

    fn input_with_delegation_expiry(
        actor_pubkey: PublicKey,
        transport: AuthTransport,
        verified_owner_pubkey: Option<PublicKey>,
        delegation_expiry: u64,
    ) -> AuthContextInput {
        let verified_delegation = verified_owner_pubkey.map(|owner_pubkey| {
            VerifiedTransportDelegation::new_unrestricted(
                owner_pubkey,
                actor_pubkey,
                Some(
                    DelegationExpiry::new(delegation_expiry)
                        .expect("synthetic delegation expiry is valid"),
                ),
            )
            .expect("synthetic owner and delegate are distinct")
        });
        let proof_method = match transport {
            AuthTransport::RelayWebSocket | AuthTransport::Audio => AuthMethod::Nip42,
            _ => AuthMethod::Nip98,
        };
        AuthContextInput::new(
            tenant(1),
            Uuid::from_u128(2),
            VerifiedNostrProof::new(
                authorization_domain(1),
                transport,
                actor_pubkey,
                proof_method,
                verified_delegation,
            )
            .expect("synthetic Nostr proof is internally consistent"),
            AuthorizedCommunityAccess::new(authorization_domain(1), Scope::all_known(), None),
        )
    }

    fn proof_in(
        domain: u128,
        transport: AuthTransport,
        actor_pubkey: PublicKey,
    ) -> VerifiedNostrProof {
        let proof_method = match transport {
            AuthTransport::RelayWebSocket | AuthTransport::Audio => AuthMethod::Nip42,
            _ => AuthMethod::Nip98,
        };
        VerifiedNostrProof::new(
            authorization_domain(domain),
            transport,
            actor_pubkey,
            proof_method,
            None,
        )
        .expect("synthetic Nostr proof is valid")
    }

    fn community_access_in(domain: u128) -> AuthorizedCommunityAccess {
        AuthorizedCommunityAccess::new(authorization_domain(domain), Scope::all_known(), None)
    }

    fn delegated_authorization(
        domain: u128,
        owner_pubkey: PublicKey,
        assertion_principal: FederatedPrincipal,
        assertion_expiry: u64,
    ) -> FederatedAuthorization {
        FederatedAuthorization::Delegated {
            owner: binding_in(domain, owner_pubkey),
            assertion: assertion(
                assertion_principal,
                AssertionTransport::TrustedProxy,
                assertion_expiry,
            ),
        }
    }

    #[test]
    fn context_preserves_server_resolved_authority() {
        let keys = Keys::generate();
        let correlation_id = Uuid::from_u128(2);
        let context = AuthContext::finalize_v1(
            AuthContextInput::new(
                tenant(1),
                correlation_id,
                VerifiedNostrProof::new(
                    authorization_domain(1),
                    AuthTransport::RelayWebSocket,
                    keys.public_key(),
                    AuthMethod::Nip42,
                    None,
                )
                .expect("synthetic Nostr proof is valid"),
                AuthorizedCommunityAccess::new(
                    authorization_domain(1),
                    vec![Scope::MessagesRead],
                    None,
                ),
            ),
            policy_not_required(),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect("Nostr-only policy is final authorization");

        assert_eq!(context.version(), AuthContextVersion::V1);
        assert_eq!(context.tenant().community().as_uuid(), &Uuid::from_u128(1));
        assert_eq!(context.correlation_id(), correlation_id);
        assert_eq!(context.transport(), AuthTransport::RelayWebSocket);
        assert_eq!(context.pubkey(), keys.public_key());
        assert_eq!(context.auth_method(), AuthMethod::Nip42);
        assert_eq!(
            context.federated_policy().requirement(),
            FederatedIdentityRequirement::NotRequired
        );
        assert!(context.has_scope(&Scope::MessagesRead));
        assert_eq!(
            context.federated_authorization(),
            &FederatedAuthorization::NotRequired
        );
    }

    #[test]
    fn direct_authorization_requires_the_authenticated_key() {
        let actor = Keys::generate();
        let other = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(other.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("a direct binding for another key must be rejected");
        assert_eq!(error, AuthContextError::DirectBindingKeyMismatch);
    }

    #[test]
    fn delegated_authorization_requires_the_verified_owner() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let context = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), principal(), 200),
            100,
        )
        .expect("verified owner and delegate match");

        assert!(matches!(
            context.federated_authorization(),
            FederatedAuthorization::Delegated { .. }
        ));
    }

    #[test]
    fn delegated_authorization_requires_verified_delegation() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), principal(), 200),
            100,
        )
        .expect_err("delegated authorization requires verifier-issued proof");

        assert_eq!(error, AuthContextError::DelegationRequired);
        assert_eq!(error.code(), "federated_delegation_required");
    }

    #[test]
    fn principal_debug_output_redacts_claim_values() {
        let principal = FederatedPrincipal::new("https://idp.example", "subject-123")
            .expect("synthetic principal is valid");
        let output = format!("{principal:?}");

        assert!(!output.contains("idp.example"));
        assert!(!output.contains("subject-123"));
        assert!(output.contains("[redacted]"));
    }

    #[test]
    fn context_debug_output_omits_tenant_host() {
        let actor = Keys::generate();
        let channel_id = Uuid::from_u128(20);
        let context = AuthContext::finalize_v1(
            AuthContextInput::new(
                tenant(1),
                Uuid::from_u128(2),
                VerifiedNostrProof::new(
                    authorization_domain(1),
                    AuthTransport::RelayWebSocket,
                    actor.public_key(),
                    AuthMethod::Nip42,
                    None,
                )
                .expect("synthetic Nostr proof is valid"),
                AuthorizedCommunityAccess::new(
                    authorization_domain(1),
                    vec![Scope::MessagesRead],
                    Some(vec![channel_id]),
                ),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect("matching direct authorization is valid");

        let output = format!("{context:?}");
        assert!(!output.contains("relay.example"));
        assert!(!output.contains("idp.example"));
        assert!(!output.contains("subject-123"));
        assert!(!output.contains(&Uuid::from_u128(1).to_string()));
        assert!(!output.contains(&Uuid::from_u128(2).to_string()));
        assert!(!output.contains(&Uuid::from_u128(10).to_string()));
        assert!(!output.contains(&channel_id.to_string()));
        assert!(!output.contains(&actor.public_key().to_hex()));
        assert!(!output.contains("MessagesRead"));
        assert!(!output.contains("scope_count"));
        assert!(!output.contains("channel_restricted"));
        assert!(output.contains("authorization_domain"));
        assert!(output.contains("[redacted]"));
    }

    #[test]
    fn direct_authorization_rejects_a_verified_owner() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("direct authorization cannot derive authority from an owner");

        assert_eq!(error, AuthContextError::DirectAuthorizationHasOwner);
    }

    #[test]
    fn delegated_authorization_requires_a_current_owner_assertion() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), principal(), 100),
            100,
        )
        .expect_err("delegated authorization must not survive owner assertion expiry");

        assert_eq!(error, AuthContextError::AssertionExpired);
    }

    #[test]
    fn delegated_authorization_rejects_a_future_owner_assertion() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Delegated {
                owner: binding(owner.public_key()),
                assertion: assertion_with_bounds_in(
                    1,
                    AuthTransport::RelayWebSocket,
                    principal(),
                    AssertionTransport::TrustedProxy,
                    Some(101),
                    200,
                ),
            },
            100,
        )
        .expect_err("delegated authorization must enforce the owner's not-before bound");

        assert_eq!(error, AuthContextError::AssertionNotYetValid);
    }

    #[test]
    fn delegated_authorization_requires_the_owner_assertion_principal() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let assertion_principal = FederatedPrincipal::new("https://idp.example", "other-subject")
            .expect("synthetic principal is valid");
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), assertion_principal, 200),
            100,
        )
        .expect_err("the current assertion must identify the bound owner");

        assert_eq!(error, AuthContextError::AssertionPrincipalMismatch);
    }

    #[test]
    fn delegated_authorization_rejects_an_expired_proof() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input_with_delegation_expiry(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
                100,
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), principal(), 200),
            100,
        )
        .expect_err("delegated authorization must not survive delegation expiry");

        assert_eq!(error, AuthContextError::DelegationExpired);
    }

    #[test]
    fn verified_nostr_proof_requires_the_authenticated_delegate() {
        let actor = Keys::generate();
        let other_delegate = Keys::generate();
        let owner = Keys::generate();
        let delegation = VerifiedTransportDelegation::new_unrestricted(
            owner.public_key(),
            other_delegate.public_key(),
            None,
        )
        .expect("synthetic owner and delegate are distinct");
        let error = VerifiedNostrProof::new(
            authorization_domain(1),
            AuthTransport::RelayWebSocket,
            actor.public_key(),
            AuthMethod::Nip42,
            Some(delegation),
        )
        .expect_err("verified proof must name the authenticated actor");

        assert_eq!(error, AuthContextError::DelegateKeyMismatch);
    }

    #[test]
    fn delegated_authorization_requires_the_bound_owner() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let other_owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(other_owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(1, owner.public_key(), principal(), 200),
            100,
        )
        .expect_err("delegated authorization must match the verified owner");

        assert_eq!(error, AuthContextError::DelegatedOwnerMismatch);
    }

    #[test]
    fn delegated_binding_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            delegated_authorization(2, owner.public_key(), principal(), 200),
            100,
        )
        .expect_err("a delegated binding from another domain must be rejected");

        assert_eq!(error, AuthContextError::BindingDomainMismatch);
    }

    #[test]
    fn zero_binding_version_is_rejected() {
        assert_eq!(
            BindingVersion::new(0),
            Err(AuthContextError::InvalidBindingVersion)
        );
    }

    #[test]
    fn nil_binding_identifier_is_rejected() {
        let actor = Keys::generate();
        let error = VersionedBindingRef::new(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            Uuid::nil(),
            principal(),
            actor.public_key(),
            BindingVersion::INITIAL,
            BindingSource::AttestedKey,
        )
        .expect_err("nil is not a stable binding identifier");

        assert_eq!(error, AuthContextError::InvalidBindingId);
        assert_eq!(error.code(), "federated_binding_invalid_id");
    }

    #[test]
    fn evidence_value_debug_output_redacts_numeric_values() {
        let assertion_expiry = AssertionExpiry::new(200).expect("synthetic expiry is valid");
        let assertion_not_before = AssertionNotBefore::new(100);
        let delegation_expiry = DelegationExpiry::new(300).expect("synthetic expiry is valid");
        let binding_version = BindingVersion::new(400).expect("synthetic version is valid");

        assert_eq!(
            format!("{assertion_expiry:?}"),
            "AssertionExpiry(\"[redacted]\")"
        );
        assert_eq!(
            format!("{assertion_not_before:?}"),
            "AssertionNotBefore(\"[redacted]\")"
        );
        assert_eq!(
            format!("{delegation_expiry:?}"),
            "DelegationExpiry(\"[redacted]\")"
        );
        assert_eq!(
            format!("{binding_version:?}"),
            "BindingVersion(\"[redacted]\")"
        );
    }

    #[test]
    fn direct_authorization_rejects_expired_assertions() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::HttpBridge, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::ClientAttached, 100),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("authorization must not survive assertion expiry");

        assert_eq!(error, AuthContextError::AssertionExpired);
        assert_eq!(error.code(), "federated_assertion_expired");
    }

    #[test]
    fn direct_authorization_rejects_a_future_assertion() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::HttpBridge, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion_with_bounds_in(
                    1,
                    AuthTransport::HttpBridge,
                    principal(),
                    AssertionTransport::ClientAttached,
                    Some(101),
                    200,
                ),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("authorization must enforce the assertion's not-before bound");

        assert_eq!(error, AuthContextError::AssertionNotYetValid);
        assert_eq!(error.code(), "federated_assertion_not_yet_valid");
    }

    #[test]
    fn direct_authorization_requires_the_assertion_principal() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(
                    FederatedPrincipal::new("https://idp.example", "other-subject")
                        .expect("synthetic principal is valid"),
                    AssertionTransport::TrustedProxy,
                    200,
                ),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("the current assertion must identify the bound principal");

        assert_eq!(error, AuthContextError::AssertionPrincipalMismatch);
        assert_eq!(error.code(), "federated_assertion_principal_mismatch");
    }

    #[test]
    fn enrolled_reason_must_match_policy_and_binding_source() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::Provisioned),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::EnrolledAttestedKey,
            },
            100,
        )
        .expect_err("provisioned mode cannot enroll during authorization");

        assert_eq!(error, AuthContextError::InvalidAuthorizationReason);
    }

    #[test]
    fn tofu_enrollment_uses_tofu_reason_with_attested_provenance() {
        let actor = Keys::generate();
        let authorization = FederatedAuthorization::Direct {
            binding: binding(actor.public_key()),
            assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
            reason: AuthorizationReason::EnrolledTofu,
        };

        let context = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::Tofu),
            authorization,
            100,
        )
        .expect("TOFU policy may retain stronger attested-key provenance");

        assert_eq!(
            context.authorization_reason(),
            AuthorizationReason::EnrolledTofu
        );
    }

    #[test]
    fn tofu_enrollment_cannot_use_attested_key_policy_reason() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::Tofu),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::EnrolledAttestedKey,
            },
            100,
        )
        .expect_err("TOFU policy must emit the TOFU enrollment reason");

        assert_eq!(error, AuthContextError::InvalidAuthorizationReason);
    }

    #[test]
    fn transport_and_proof_method_must_agree() {
        let actor = Keys::generate();
        let error = VerifiedNostrProof::new(
            authorization_domain(1),
            AuthTransport::RelayWebSocket,
            actor.public_key(),
            AuthMethod::Nip98,
            None,
        )
        .expect_err("HTTP proof must not authorize a relay WebSocket");
        assert_eq!(error, AuthContextError::TransportProofMismatch);
    }

    #[test]
    fn binding_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding_in(2, actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("a binding from another domain must be rejected");

        assert_eq!(error, AuthContextError::BindingDomainMismatch);
        assert_eq!(error.code(), "federated_binding_domain_mismatch");
    }

    #[test]
    fn nostr_only_authorization_may_preserve_a_verified_owner() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let context = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_not_required(),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect("Nostr delegation remains independent of federated policy");

        assert_eq!(context.agent_owner_pubkey(), Some(owner.public_key()));
        assert_eq!(
            context.authorization_reason(),
            AuthorizationReason::NostrOnly
        );
    }

    #[test]
    fn transport_delegation_rejects_self_reference() {
        let actor = Keys::generate();
        let error = VerifiedTransportDelegation::new_unrestricted(
            actor.public_key(),
            actor.public_key(),
            None,
        )
        .expect_err("an actor cannot be its own verified owner");

        assert_eq!(error, AuthContextError::SelfDelegation);
    }

    #[test]
    fn transport_delegation_is_explicitly_transport_wide() {
        let owner = Keys::generate();
        let delegate = Keys::generate();
        let delegation = VerifiedTransportDelegation::new_unrestricted(
            owner.public_key(),
            delegate.public_key(),
            None,
        )
        .expect("synthetic owner and delegate are distinct");

        assert_eq!(delegation.capability(), DelegationCapability::TransportWide);
    }

    #[test]
    fn required_policy_rejects_nostr_only_authorization() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect_err("required federated identity cannot be bypassed by the caller");

        assert_eq!(error, AuthContextError::FederatedIdentityRequired);
        assert_eq!(error.code(), "federated_identity_required");
    }

    #[test]
    fn not_required_policy_rejects_federated_authorization() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_not_required(),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion(principal(), AssertionTransport::TrustedProxy, 200),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("federated evidence cannot override the resolved domain policy");

        assert_eq!(error, AuthContextError::UnexpectedFederatedAuthorization);
        assert_eq!(error.code(), "federated_authorization_unexpected");
    }

    #[test]
    fn nostr_proof_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            AuthContextInput::new(
                tenant(1),
                Uuid::from_u128(2),
                proof_in(2, AuthTransport::RelayWebSocket, actor.public_key()),
                community_access_in(1),
            ),
            policy_not_required(),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect_err("a Nostr proof from another domain must be rejected");

        assert_eq!(error, AuthContextError::NostrProofDomainMismatch);
        assert_eq!(error.code(), "nostr_proof_domain_mismatch");
    }

    #[test]
    fn federated_policy_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            ResolvedFederatedPolicy::not_required(authorization_domain(2)),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect_err("policy from another domain must be rejected");

        assert_eq!(error, AuthContextError::PolicyDomainMismatch);
        assert_eq!(error.code(), "federated_policy_domain_mismatch");
    }

    #[test]
    fn community_admission_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            AuthContextInput::new(
                tenant(1),
                Uuid::from_u128(2),
                proof_in(1, AuthTransport::RelayWebSocket, actor.public_key()),
                community_access_in(2),
            ),
            policy_not_required(),
            FederatedAuthorization::NotRequired,
            100,
        )
        .expect_err("community admission from another domain must be rejected");

        assert_eq!(error, AuthContextError::CommunityAccessDomainMismatch);
        assert_eq!(error.code(), "community_access_domain_mismatch");
    }

    #[test]
    fn assertion_cannot_cross_authorization_domains() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion_in(
                    2,
                    AuthTransport::RelayWebSocket,
                    principal(),
                    AssertionTransport::TrustedProxy,
                    200,
                ),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("an assertion from another domain must be rejected");

        assert_eq!(error, AuthContextError::AssertionDomainMismatch);
        assert_eq!(error.code(), "federated_assertion_domain_mismatch");
    }

    #[test]
    fn assertion_must_match_the_authorized_transport() {
        let actor = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(actor.public_key(), AuthTransport::RelayWebSocket, None),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Direct {
                binding: binding(actor.public_key()),
                assertion: assertion_in(
                    1,
                    AuthTransport::HttpBridge,
                    principal(),
                    AssertionTransport::TrustedProxy,
                    200,
                ),
                reason: AuthorizationReason::ExistingBinding,
            },
            100,
        )
        .expect_err("an assertion verified for another transport must be rejected");

        assert_eq!(error, AuthContextError::AssertionTransportMismatch);
        assert_eq!(error.code(), "federated_assertion_transport_mismatch");
    }

    #[test]
    fn delegated_assertion_must_match_the_authorized_transport() {
        let actor = Keys::generate();
        let owner = Keys::generate();
        let error = AuthContext::finalize_v1(
            input(
                actor.public_key(),
                AuthTransport::RelayWebSocket,
                Some(owner.public_key()),
            ),
            policy_required(EnrollmentMode::AttestedKey),
            FederatedAuthorization::Delegated {
                owner: binding(owner.public_key()),
                assertion: assertion_in(
                    1,
                    AuthTransport::HttpBridge,
                    principal(),
                    AssertionTransport::TrustedProxy,
                    200,
                ),
            },
            100,
        )
        .expect_err("a delegated assertion for another transport must be rejected");

        assert_eq!(error, AuthContextError::AssertionTransportMismatch);
    }
}
