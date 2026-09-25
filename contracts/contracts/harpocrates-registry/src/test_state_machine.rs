//! Deterministic registry state-machine fuzzing (#93).
//!
//! The harness below models authorized and adversarial registry transitions,
//! generates bounded random command streams from reproducible seeds, shrinks a
//! failing stream by command deletion/simplification, and checks the real
//! Soroban contract boundary after every step.
//!
//! Failure messages intentionally print only seeds, command variants, bounded
//! slot numbers, and error codes. They never include proof bytes, public input
//! bytes, witnesses, credential metadata, signatures, or media.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, Env, IntoVal, InvokeError, Symbol, Val, Vec as SorobanVec,
};
use std::{format, string::String, vec::Vec as StdVec};

const START_TIMESTAMP: u64 = 1_700_000_000;
const KEY_POOL: u8 = 8;
const GENERATED_STEPS: usize = 64;
const MAX_LOCAL_FUZZ_RUNS: usize = 512;
const MAX_FUZZ_CPU: u64 = 20_000_000;
const MAX_FUZZ_MEM: u64 = 16_000_000;

const REGRESSION_SEEDS: &[u64] = &[
    0x93_0000_0000_0001,
    0x93_0000_0000_0002,
    0x93_0000_0000_0003,
    0x93_0000_0000_0004,
    0x93_0000_0000_0005,
    0x93_D0C5AFE_BADF00D,
    0x0093_A11C_E5EC_0FFE,
    0x935A_7064_0000_0001,
];

#[contract]
struct MockStateMachineVerifier;

#[contractimpl]
impl MockStateMachineVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        // Accept all canonical frame shapes: 128-byte revocation witness,
        // 160-byte silent witness, and 224-byte scoped silent witness.
        if (len != 128 && len != 160 && len != 224) || proof.is_empty() {
            panic!("invalid state-machine proof");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActorId {
    Admin0,
    PendingA,
    PendingB,
    SourceA,
    SourceB,
    IssuerA,
    IssuerB,
    Stranger,
}

impl ActorId {
    fn index(self) -> usize {
        match self {
            ActorId::Admin0 => 0,
            ActorId::PendingA => 1,
            ActorId::PendingB => 2,
            ActorId::SourceA => 3,
            ActorId::SourceB => 4,
            ActorId::IssuerA => 5,
            ActorId::IssuerB => 6,
            ActorId::Stranger => 7,
        }
    }
}

const ACTORS: [ActorId; 8] = [
    ActorId::Admin0,
    ActorId::PendingA,
    ActorId::PendingB,
    ActorId::SourceA,
    ActorId::SourceB,
    ActorId::IssuerA,
    ActorId::IssuerB,
    ActorId::Stranger,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HashDomain {
    Proof,
    Video,
    Metadata,
    Nullifier,
    CredentialRoot,
    RevocationRoot,
}

impl HashDomain {
    fn tag(self) -> u8 {
        match self {
            HashDomain::Proof => 0xA1,
            HashDomain::Video => 0xB2,
            HashDomain::Metadata => 0xC3,
            HashDomain::Nullifier => 0xD4,
            HashDomain::CredentialRoot => 0xE5,
            HashDomain::RevocationRoot => 0xF6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuerState {
    Missing,
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootState {
    Missing,
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofMode {
    Valid,
    Empty,
    Oversized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SilentInputMode {
    Correct,
    WrongVideo,
    Short,
    Oversized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevocationInputMode {
    Correct,
    WrongDomain,
    WrongRoot,
    Short,
    Oversized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbortKind {
    CancelledBeforeSubmit,
    TimedOutBeforeSubmit,
    PartialClientWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    RegisterSource {
        source: ActorId,
        proof: u8,
        video: u8,
        metadata: u8,
    },
    RegisterSeal {
        issuer: ActorId,
        proof: u8,
        video: u8,
        metadata: u8,
    },
    RegisterAnonymous {
        proof: u8,
        video: u8,
        metadata: u8,
        nullifier: u8,
        credential_root: u8,
        proof_mode: ProofMode,
    },
    RegisterAnonymousVerified {
        proof: u8,
        video: u8,
        metadata: u8,
        nullifier: u8,
        credential_root: u8,
        input_mode: SilentInputMode,
        proof_mode: ProofMode,
    },
    RevokeProof {
        admin: ActorId,
        proof: u8,
    },
    AddIssuer {
        admin: ActorId,
        issuer: ActorId,
        metadata: u8,
    },
    RevokeIssuer {
        admin: ActorId,
        issuer: ActorId,
    },
    AddCredentialRoot {
        admin: ActorId,
        root: u8,
        metadata: u8,
    },
    RevokeCredentialRoot {
        admin: ActorId,
        root: u8,
    },
    SetVerifier {
        admin: ActorId,
        verifier: u8,
    },
    SetProofTtl {
        admin: ActorId,
        ttl: u64,
    },
    AdvanceTime {
        delta: u64,
    },
    ProposeAdmin {
        admin: ActorId,
        pending_admin: ActorId,
    },
    CancelAdminTransfer {
        admin: ActorId,
    },
    AcceptAdmin {
        pending_admin: ActorId,
    },
    SetRevocationRoot {
        admin: ActorId,
        root: u8,
    },
    CheckNonRevocation {
        nullifier: u8,
        revocation_root: u8,
        credential_root: u8,
        input_mode: RevocationInputMode,
        proof_mode: ProofMode,
    },
    Reinit {
        admin: ActorId,
    },
    UpgradeStorage {
        admin: ActorId,
    },
    Abort {
        kind: AbortKind,
    },
}

#[derive(Clone, Debug)]
struct ModelProof {
    proof: u8,
    video: u8,
    metadata: u8,
    tier: u32,
    status: u32,
    created_at: u64,
    expires_at: u64,
    source: Option<ActorId>,
    issuer: Option<ActorId>,
    nullifier: Option<u8>,
}

#[derive(Clone, Debug)]
struct Model {
    admin: ActorId,
    pending_admin: Option<ActorId>,
    issuers: [IssuerState; 8],
    issuer_metadata: [u8; 8],
    credential_roots: [RootState; KEY_POOL as usize],
    credential_root_metadata: [u8; KEY_POOL as usize],
    credential_root_issued_at: [u64; KEY_POOL as usize],
    verifier: Option<u8>,
    proof_ttl: u64,
    revocation_root: Option<u8>,
    now: u64,
    schema_version: u32,
    proofs: StdVec<ModelProof>,
    nullifiers: StdVec<u8>,
}

impl Model {
    fn new() -> Self {
        let mut issuers = [IssuerState::Missing; 8];
        issuers[ActorId::IssuerA.index()] = IssuerState::Active;
        let mut issuer_metadata = [0u8; 8];
        issuer_metadata[ActorId::IssuerA.index()] = 0;

        let mut credential_roots = [RootState::Missing; KEY_POOL as usize];
        credential_roots[0] = RootState::Active;
        let mut credential_root_metadata = [0u8; KEY_POOL as usize];
        credential_root_metadata[0] = 1;
        let mut credential_root_issued_at = [0u64; KEY_POOL as usize];
        credential_root_issued_at[0] = START_TIMESTAMP;

        Self {
            admin: ActorId::Admin0,
            pending_admin: None,
            issuers,
            issuer_metadata,
            credential_roots,
            credential_root_metadata,
            credential_root_issued_at,
            verifier: None,
            proof_ttl: 0,
            revocation_root: None,
            now: START_TIMESTAMP,
            schema_version: 1,
            proofs: StdVec::new(),
            nullifiers: StdVec::new(),
        }
    }

    fn require_admin(&self, actor: ActorId) -> Result<(), RegistryError> {
        if actor == self.admin {
            Ok(())
        } else {
            Err(RegistryError::Unauthorized)
        }
    }

    fn require_unique(&self, proof: u8, video: u8) -> Result<(), RegistryError> {
        if self.proof_exists(proof) {
            return Err(RegistryError::DuplicateProof);
        }
        if self.video_exists(video) {
            return Err(RegistryError::DuplicateVideo);
        }
        Ok(())
    }

    fn require_active_root(&self, root: u8) -> Result<(), RegistryError> {
        match self.credential_roots[slot(root) as usize] {
            RootState::Missing => Err(RegistryError::UnknownCredentialRoot),
            RootState::Revoked => Err(RegistryError::RevokedCredentialRoot),
            RootState::Active => Ok(()),
        }
    }

    fn expected_expires_at(&self) -> u64 {
        if self.proof_ttl == 0 {
            0
        } else {
            self.now.saturating_add(self.proof_ttl)
        }
    }

    fn proof_exists(&self, proof: u8) -> bool {
        self.find_proof(proof).is_some()
    }

    fn video_exists(&self, video: u8) -> bool {
        self.proofs.iter().any(|record| record.video == slot(video))
    }

    fn nullifier_exists(&self, nullifier: u8) -> bool {
        self.nullifiers
            .iter()
            .any(|stored| *stored == slot(nullifier))
    }

    fn find_proof(&self, proof: u8) -> Option<&ModelProof> {
        let proof = slot(proof);
        self.proofs.iter().find(|record| record.proof == proof)
    }

    fn find_by_video(&self, video: u8) -> Option<&ModelProof> {
        let video = slot(video);
        self.proofs.iter().find(|record| record.video == video)
    }

    fn expected_status(&self, record: &ModelProof) -> ProofVerificationStatus {
        if record.status == STATUS_REVOKED {
            ProofVerificationStatus::Revoked
        } else if record.expires_at > 0 && self.now > record.expires_at {
            ProofVerificationStatus::Expired
        } else {
            ProofVerificationStatus::Valid
        }
    }
}

struct Fixture {
    env: Env,
    contract_id: Address,
    actors: [Address; 8],
    verifiers: [Address; 2],
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(START_TIMESTAMP);

        let contract_id = env.register(HarpocratesRegistry, ());
        let verifier_a = env.register(MockStateMachineVerifier, ());
        let verifier_b = env.register(MockStateMachineVerifier, ());
        let actors = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];

        let client = HarpocratesRegistryClient::new(&env, &contract_id);
        client.init(&actors[ActorId::Admin0.index()]);
        client.add_issuer(
            &actors[ActorId::Admin0.index()],
            &actors[ActorId::IssuerA.index()],
            &key(&env, HashDomain::Metadata, 0),
        );
        client.add_credential_root(
            &actors[ActorId::Admin0.index()],
            &key(&env, HashDomain::CredentialRoot, 0),
            &key(&env, HashDomain::Metadata, 1),
        );
        let _ = env.events().all();

        Self {
            env,
            contract_id,
            actors,
            verifiers: [verifier_a, verifier_b],
        }
    }

    fn client(&self) -> HarpocratesRegistryClient<'_> {
        HarpocratesRegistryClient::new(&self.env, &self.contract_id)
    }

    fn actor(&self, actor: ActorId) -> Address {
        self.actors[actor.index()].clone()
    }

    fn verifier(&self, slot: u8) -> Address {
        self.verifiers[(slot as usize) % self.verifiers.len()].clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallFailure {
    Contract(RegistryError),
    Invoke,
}

type CallResult<T> = Result<T, CallFailure>;
type CheckResult = Result<(), String>;

fn slot(value: u8) -> u8 {
    value % KEY_POOL
}

fn actor_from(value: u8) -> ActorId {
    ACTORS[(value as usize) % ACTORS.len()]
}

fn proof_mode_from(value: u8) -> ProofMode {
    match value % 8 {
        0 => ProofMode::Empty,
        1 => ProofMode::Oversized,
        _ => ProofMode::Valid,
    }
}

fn silent_input_mode_from(value: u8) -> SilentInputMode {
    match value % 8 {
        0 => SilentInputMode::WrongVideo,
        1 => SilentInputMode::Short,
        2 => SilentInputMode::Oversized,
        _ => SilentInputMode::Correct,
    }
}

fn revocation_input_mode_from(value: u8) -> RevocationInputMode {
    match value % 10 {
        0 => RevocationInputMode::WrongDomain,
        1 => RevocationInputMode::WrongRoot,
        2 => RevocationInputMode::Short,
        3 => RevocationInputMode::Oversized,
        _ => RevocationInputMode::Correct,
    }
}

fn ttl_from(value: u8) -> u64 {
    match value % 8 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 10,
        4 => 60,
        5 => 3_600,
        6 => u64::MAX,
        _ => 86_400,
    }
}

fn delta_from(value: u8) -> u64 {
    match value % 8 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 11,
        4 => 61,
        5 => 3_601,
        6 => 86_401,
        _ => u64::MAX,
    }
}

fn key(env: &Env, domain: HashDomain, value: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    let slot = slot(value);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = domain
            .tag()
            .wrapping_add(slot.wrapping_mul(17))
            .wrapping_add(index as u8);
    }
    bytes[0] = domain.tag();
    bytes[1] = slot;
    BytesN::from_array(env, &bytes)
}

fn proof_bytes(env: &Env, mode: ProofMode) -> Bytes {
    match mode {
        ProofMode::Valid => Bytes::from_array(env, &[0xA5, 0x5A, 0xC3, 0x3C]),
        ProofMode::Empty => Bytes::from_array(env, &[]),
        ProofMode::Oversized => Bytes::from_array(env, &[0xEA; 256]),
    }
}

fn silent_public_inputs(
    env: &Env,
    video: u8,
    credential_root: u8,
    nullifier: u8,
    mode: SilentInputMode,
) -> Bytes {
    match mode {
        SilentInputMode::Short => Bytes::from_array(env, &[0x11; 159]),
        SilentInputMode::Oversized => Bytes::from_array(env, &[0x22; 161]),
        SilentInputMode::Correct | SilentInputMode::WrongVideo => {
            let input_video = match mode {
                SilentInputMode::WrongVideo => slot(video).wrapping_add(1) % KEY_POOL,
                _ => slot(video),
            };
            let video_hash = key(env, HashDomain::Video, input_video);
            let credential_root = key(env, HashDomain::CredentialRoot, credential_root);
            let nullifier = key(env, HashDomain::Nullifier, nullifier);
            let mut vh = [0u8; 32];
            let mut cr = [0u8; 32];
            let mut nu = [0u8; 32];
            video_hash.copy_into_slice(&mut vh);
            credential_root.copy_into_slice(&mut cr);
            nullifier.copy_into_slice(&mut nu);

            let mut bytes = [0u8; 160];
            bytes[16..32].copy_from_slice(&vh[..16]);
            bytes[48..64].copy_from_slice(&vh[16..]);
            bytes[64..96].copy_from_slice(&cr);
            bytes[96..128].copy_from_slice(&nu);
            // Fifth field word: the canonical silent-witness domain tag.
            let tag = expected_domain_tag(env);
            let mut t = [0u8; 32];
            tag.copy_into_slice(&mut t);
            bytes[128..160].copy_from_slice(&t);
            Bytes::from_array(env, &bytes)
        }
    }
}

fn revocation_public_inputs(
    env: &Env,
    revocation_root: u8,
    nullifier: u8,
    credential_root: u8,
    mode: RevocationInputMode,
) -> Bytes {
    match mode {
        RevocationInputMode::Short => Bytes::from_array(env, &[0x33; 127]),
        RevocationInputMode::Oversized => Bytes::from_array(env, &[0x44; 129]),
        RevocationInputMode::Correct
        | RevocationInputMode::WrongDomain
        | RevocationInputMode::WrongRoot => {
            let revocation_root = match mode {
                RevocationInputMode::WrongRoot => key(env, HashDomain::Metadata, 6),
                _ => key(env, HashDomain::RevocationRoot, revocation_root),
            };
            let nullifier = key(env, HashDomain::Nullifier, nullifier);
            let domain_separator = if mode == RevocationInputMode::WrongDomain {
                key(env, HashDomain::Metadata, 7)
            } else {
                BytesN::from_array(env, &REVOCATION_DOMAIN_SEPARATOR)
            };
            let credential_root = key(env, HashDomain::CredentialRoot, credential_root);

            let mut rr = [0u8; 32];
            let mut nu = [0u8; 32];
            let mut ds = [0u8; 32];
            let mut cr = [0u8; 32];
            revocation_root.copy_into_slice(&mut rr);
            nullifier.copy_into_slice(&mut nu);
            domain_separator.copy_into_slice(&mut ds);
            credential_root.copy_into_slice(&mut cr);

            let mut bytes = [0u8; 128];
            bytes[0..32].copy_from_slice(&rr);
            bytes[32..64].copy_from_slice(&nu);
            bytes[64..96].copy_from_slice(&ds);
            bytes[96..128].copy_from_slice(&cr);
            Bytes::from_array(env, &bytes)
        }
    }
}

fn unpack<T, ConversionError>(
    result: Result<Result<T, ConversionError>, Result<RegistryError, InvokeError>>,
) -> CallResult<T> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(CallFailure::Invoke),
        Err(Ok(error)) => Err(CallFailure::Contract(error)),
        Err(Err(_)) => Err(CallFailure::Invoke),
    }
}

fn invoke_record(fixture: &Fixture, name: &str, args: SorobanVec<Val>) -> CallResult<ProofRecord> {
    unpack(
        fixture
            .env
            .try_invoke_contract::<ProofRecord, RegistryError>(
                &fixture.contract_id,
                &Symbol::new(&fixture.env, name),
                args,
            ),
    )
}

fn invoke_unit(fixture: &Fixture, name: &str, args: SorobanVec<Val>) -> CallResult<()> {
    unpack(fixture.env.try_invoke_contract::<(), RegistryError>(
        &fixture.contract_id,
        &Symbol::new(&fixture.env, name),
        args,
    ))
}

fn args(fixture: &Fixture) -> SorobanVec<Val> {
    SorobanVec::new(&fixture.env)
}

struct ExpectedRecordSpec {
    proof: u8,
    video: u8,
    metadata: u8,
    tier: u32,
    source: Option<ActorId>,
    issuer: Option<ActorId>,
    nullifier: Option<u8>,
}

fn expected_record(model: &Model, spec: ExpectedRecordSpec) -> ModelProof {
    ModelProof {
        proof: slot(spec.proof),
        video: slot(spec.video),
        metadata: slot(spec.metadata),
        tier: spec.tier,
        status: STATUS_REGISTERED,
        created_at: model.now,
        expires_at: model.expected_expires_at(),
        source: spec.source,
        issuer: spec.issuer,
        nullifier: spec.nullifier.map(slot),
    }
}

fn compare_error(error: CallFailure, expected: RegistryError, label: &str) -> CheckResult {
    match error {
        CallFailure::Contract(actual) if actual == expected => Ok(()),
        other => Err(format!(
            "{label} returned {other:?}; expected contract error {expected:?}"
        )),
    }
}

fn compare_unit(
    actual: CallResult<()>,
    expected: Result<(), RegistryError>,
    label: &str,
) -> CheckResult {
    match (actual, expected) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(actual), Err(expected)) => compare_error(actual, expected, label),
        (Ok(()), Err(expected)) => Err(format!("{label} succeeded; expected {expected:?}")),
        (Err(actual), Ok(())) => Err(format!("{label} failed with {actual:?}; expected success")),
    }
}

fn compare_record(
    actual: CallResult<ProofRecord>,
    expected: Result<ModelProof, RegistryError>,
    fixture: &Fixture,
    label: &str,
) -> Result<Option<ModelProof>, String> {
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => {
            assert_record_matches(fixture, &actual, &expected, label)?;
            Ok(Some(expected))
        }
        (Err(actual), Err(expected)) => {
            compare_error(actual, expected, label)?;
            Ok(None)
        }
        (Ok(_), Err(expected)) => Err(format!("{label} succeeded; expected {expected:?}")),
        (Err(actual), Ok(_)) => Err(format!("{label} failed with {actual:?}; expected success")),
    }
}

fn assert_record_matches(
    fixture: &Fixture,
    actual: &ProofRecord,
    expected: &ModelProof,
    label: &str,
) -> CheckResult {
    if actual.video_hash != key(&fixture.env, HashDomain::Video, expected.video) {
        return Err(format!("{label} returned unexpected video_hash"));
    }
    if actual.metadata_hash != key(&fixture.env, HashDomain::Metadata, expected.metadata) {
        return Err(format!("{label} returned unexpected metadata_hash"));
    }
    if actual.tier != expected.tier {
        return Err(format!(
            "{label} returned tier {}; expected {}",
            actual.tier, expected.tier
        ));
    }
    if actual.status != expected.status {
        return Err(format!(
            "{label} returned status {}; expected {}",
            actual.status, expected.status
        ));
    }
    if actual.created_at != expected.created_at {
        return Err(format!(
            "{label} returned created_at {}; expected {}",
            actual.created_at, expected.created_at
        ));
    }
    if actual.expires_at != expected.expires_at {
        return Err(format!(
            "{label} returned expires_at {}; expected {}",
            actual.expires_at, expected.expires_at
        ));
    }

    let expected_source = expected.source.map(|source| fixture.actor(source));
    if actual.source != expected_source {
        return Err(format!("{label} returned unexpected source"));
    }

    let expected_issuer = expected.issuer.map(|issuer| fixture.actor(issuer));
    if actual.issuer != expected_issuer {
        return Err(format!("{label} returned unexpected issuer"));
    }

    let expected_nullifier = expected
        .nullifier
        .map(|nullifier| key(&fixture.env, HashDomain::Nullifier, nullifier));
    if actual.nullifier != expected_nullifier {
        return Err(format!("{label} returned unexpected nullifier"));
    }

    Ok(())
}

fn apply_command(fixture: &Fixture, model: &mut Model, command: Command) -> CheckResult {
    let _ = fixture.env.events().all();
    fixture.env.cost_estimate().budget().reset_unlimited();

    let expected_events = match command {
        Command::RegisterSource {
            source,
            proof,
            video,
            metadata,
        } => {
            let expected = model.require_unique(proof, video).map(|_| {
                expected_record(
                    model,
                    ExpectedRecordSpec {
                        proof,
                        video,
                        metadata,
                        tier: TIER_CONSISTENT_SOURCE,
                        source: Some(source),
                        issuer: None,
                        nullifier: None,
                    },
                )
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(source).into_val(&fixture.env));
            call_args.push_back(key(&fixture.env, HashDomain::Video, video).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );
            call_args.push_back(key(&fixture.env, HashDomain::Proof, proof).into_val(&fixture.env));

            if let Some(record) = compare_record(
                invoke_record(fixture, "register_source", call_args),
                expected,
                fixture,
                "register_source",
            )? {
                model.proofs.push(record);
                // 3 = proof, reg + proof, history + envelope, metadatabound (#317)
                3
            } else {
                0
            }
        }
        Command::RegisterSeal {
            issuer,
            proof,
            video,
            metadata,
        } => {
            let expected = model.require_unique(proof, video).and_then(|_| {
                if model.issuers[issuer.index()] == IssuerState::Active {
                    Ok(expected_record(
                        model,
                        ExpectedRecordSpec {
                            proof,
                            video,
                            metadata,
                            tier: TIER_PUBLIC_SEAL,
                            source: None,
                            issuer: Some(issuer),
                            nullifier: None,
                        },
                    ))
                } else {
                    Err(RegistryError::UnknownIssuer)
                }
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(issuer).into_val(&fixture.env));
            call_args.push_back(key(&fixture.env, HashDomain::Video, video).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );
            call_args.push_back(key(&fixture.env, HashDomain::Proof, proof).into_val(&fixture.env));

            if let Some(record) = compare_record(
                invoke_record(fixture, "register_seal", call_args),
                expected,
                fixture,
                "register_seal",
            )? {
                model.proofs.push(record);
                // 3 = proof, reg + proof, history + envelope, metadatabound (#317)
                3
            } else {
                0
            }
        }
        Command::RegisterAnonymous {
            proof,
            video,
            metadata,
            nullifier,
            credential_root,
            proof_mode,
        } => {
            let expected = model
                .require_unique(proof, video)
                .and_then(|_| {
                    if model.nullifier_exists(nullifier) {
                        Err(RegistryError::DuplicateNullifier)
                    } else {
                        Ok(())
                    }
                })
                .and_then(|_| {
                    if proof_mode == ProofMode::Empty {
                        Err(RegistryError::InvalidProof)
                    } else {
                        Ok(())
                    }
                })
                .and_then(|_| model.require_active_root(credential_root))
                .map(|_| {
                    expected_record(
                        model,
                        ExpectedRecordSpec {
                            proof,
                            video,
                            metadata,
                            tier: TIER_SILENT_WITNESS,
                            source: None,
                            issuer: None,
                            nullifier: Some(nullifier),
                        },
                    )
                });

            let mut call_args = args(fixture);
            call_args.push_back(key(&fixture.env, HashDomain::Video, video).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );
            call_args.push_back(key(&fixture.env, HashDomain::Proof, proof).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Nullifier, nullifier).into_val(&fixture.env),
            );
            call_args.push_back(
                key(&fixture.env, HashDomain::CredentialRoot, credential_root)
                    .into_val(&fixture.env),
            );
            call_args.push_back(proof_bytes(&fixture.env, proof_mode).into_val(&fixture.env));

            if let Some(record) = compare_record(
                invoke_record(fixture, "register_anonymous", call_args),
                expected,
                fixture,
                "register_anonymous",
            )? {
                model.nullifiers.push(slot(nullifier));
                model.proofs.push(record);
                // 3 = proof, reg + proof, history + envelope, metadatabound (#317)
                3
            } else {
                0
            }
        }
        Command::RegisterAnonymousVerified {
            proof,
            video,
            metadata,
            nullifier,
            credential_root,
            input_mode,
            proof_mode,
        } => {
            let expected = model
                .require_unique(proof, video)
                .and(match input_mode {
                    SilentInputMode::Short | SilentInputMode::Oversized => {
                        Err(RegistryError::InvalidPublicInputs)
                    }
                    SilentInputMode::WrongVideo => Err(RegistryError::InvalidPublicInputs),
                    SilentInputMode::Correct => Ok(()),
                })
                .and_then(|_| model.require_active_root(credential_root))
                .and_then(|_| {
                    if model.nullifier_exists(nullifier) {
                        Err(RegistryError::DuplicateNullifier)
                    } else {
                        Ok(())
                    }
                })
                .and_then(|_| {
                    if model.verifier.is_none() {
                        Err(RegistryError::VerifierNotSet)
                    } else if proof_mode == ProofMode::Empty {
                        Err(RegistryError::InvalidProof)
                    } else {
                        Ok(())
                    }
                })
                .map(|_| {
                    expected_record(
                        model,
                        ExpectedRecordSpec {
                            proof,
                            video,
                            metadata,
                            tier: TIER_SILENT_WITNESS,
                            source: None,
                            issuer: None,
                            nullifier: Some(nullifier),
                        },
                    )
                });

            let mut call_args = args(fixture);
            call_args.push_back(key(&fixture.env, HashDomain::Video, video).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );
            call_args.push_back(key(&fixture.env, HashDomain::Proof, proof).into_val(&fixture.env));
            call_args.push_back(
                silent_public_inputs(&fixture.env, video, credential_root, nullifier, input_mode)
                    .into_val(&fixture.env),
            );
            call_args.push_back(proof_bytes(&fixture.env, proof_mode).into_val(&fixture.env));

            if let Some(record) = compare_record(
                invoke_record(fixture, "register_anonymous_verified", call_args),
                expected,
                fixture,
                "register_anonymous_verified",
            )? {
                model.nullifiers.push(slot(nullifier));
                model.proofs.push(record);
                // 3 = proof, reg + proof, history + envelope, metadatabound (#317)
                3
            } else {
                0
            }
        }
        Command::RevokeProof { admin, proof } => {
            let expected = model.require_admin(admin).and_then(|_| {
                if model.proof_exists(proof) {
                    Ok(())
                } else {
                    Err(RegistryError::DuplicateProof)
                }
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(key(&fixture.env, HashDomain::Proof, proof).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "revoke_proof", call_args),
                expected,
                "revoke_proof",
            )?;
            if expected.is_ok() {
                if let Some(record) = model
                    .proofs
                    .iter_mut()
                    .find(|record| record.proof == slot(proof))
                {
                    record.status = STATUS_REVOKED;
                }
                2
            } else {
                0
            }
        }
        Command::AddIssuer {
            admin,
            issuer,
            metadata,
        } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(fixture.actor(issuer).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );

            compare_unit(
                invoke_unit(fixture, "add_issuer", call_args),
                expected,
                "add_issuer",
            )?;
            if expected.is_ok() {
                model.issuers[issuer.index()] = IssuerState::Active;
                model.issuer_metadata[issuer.index()] = slot(metadata);
                1
            } else {
                0
            }
        }
        Command::RevokeIssuer { admin, issuer } => {
            let expected = model.require_admin(admin).and_then(|_| {
                if model.issuers[issuer.index()] == IssuerState::Missing {
                    Err(RegistryError::UnknownIssuer)
                } else {
                    Ok(())
                }
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(fixture.actor(issuer).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "revoke_issuer", call_args),
                expected,
                "revoke_issuer",
            )?;
            if expected.is_ok() {
                model.issuers[issuer.index()] = IssuerState::Revoked;
                1
            } else {
                0
            }
        }
        Command::AddCredentialRoot {
            admin,
            root,
            metadata,
        } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::CredentialRoot, root).into_val(&fixture.env),
            );
            call_args.push_back(
                key(&fixture.env, HashDomain::Metadata, metadata).into_val(&fixture.env),
            );

            compare_unit(
                invoke_unit(fixture, "add_credential_root", call_args),
                expected,
                "add_credential_root",
            )?;
            if expected.is_ok() {
                model.credential_roots[slot(root) as usize] = RootState::Active;
                model.credential_root_metadata[slot(root) as usize] = slot(metadata);
                model.credential_root_issued_at[slot(root) as usize] = model.now;
                1
            } else {
                0
            }
        }
        Command::RevokeCredentialRoot { admin, root } => {
            let expected = model.require_admin(admin).and_then(|_| {
                if model.credential_roots[slot(root) as usize] == RootState::Missing {
                    Err(RegistryError::UnknownCredentialRoot)
                } else {
                    Ok(())
                }
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::CredentialRoot, root).into_val(&fixture.env),
            );

            compare_unit(
                invoke_unit(fixture, "revoke_credential_root", call_args),
                expected,
                "revoke_credential_root",
            )?;
            if expected.is_ok() {
                model.credential_roots[slot(root) as usize] = RootState::Revoked;
                1
            } else {
                0
            }
        }
        Command::SetVerifier { admin, verifier } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(fixture.verifier(verifier).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "set_verifier", call_args),
                expected,
                "set_verifier",
            )?;
            if expected.is_ok() {
                model.verifier = Some(verifier % 2);
                1
            } else {
                0
            }
        }
        Command::SetProofTtl { admin, ttl } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(ttl.into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "set_proof_ttl", call_args),
                expected,
                "set_proof_ttl",
            )?;
            if expected.is_ok() {
                model.proof_ttl = ttl;
            }
            0
        }
        Command::AdvanceTime { delta } => {
            model.now = model.now.saturating_add(delta);
            fixture.env.ledger().set_timestamp(model.now);
            0
        }
        Command::ProposeAdmin {
            admin,
            pending_admin,
        } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(fixture.actor(pending_admin).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "propose_admin", call_args),
                expected,
                "propose_admin",
            )?;
            if expected.is_ok() {
                model.pending_admin = Some(pending_admin);
                1
            } else {
                0
            }
        }
        Command::CancelAdminTransfer { admin } => {
            let expected = model.require_admin(admin).and_then(|_| {
                if model.pending_admin.is_some() {
                    Ok(())
                } else {
                    Err(RegistryError::NoPendingAdmin)
                }
            });

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "cancel_admin_transfer", call_args),
                expected,
                "cancel_admin_transfer",
            )?;
            if expected.is_ok() {
                model.pending_admin = None;
                1
            } else {
                0
            }
        }
        Command::AcceptAdmin { pending_admin } => {
            let expected = match model.pending_admin {
                None => Err(RegistryError::NoPendingAdmin),
                Some(expected_admin) if expected_admin != pending_admin => {
                    Err(RegistryError::Unauthorized)
                }
                Some(_) => Ok(()),
            };

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(pending_admin).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "accept_admin", call_args),
                expected,
                "accept_admin",
            )?;
            if expected.is_ok() {
                model.admin = pending_admin;
                model.pending_admin = None;
                1
            } else {
                0
            }
        }
        Command::SetRevocationRoot { admin, root } => {
            let expected = model.require_admin(admin);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));
            call_args.push_back(
                key(&fixture.env, HashDomain::RevocationRoot, root).into_val(&fixture.env),
            );

            compare_unit(
                invoke_unit(fixture, "set_revocation_root", call_args),
                expected,
                "set_revocation_root",
            )?;
            if expected.is_ok() {
                model.revocation_root = Some(slot(root));
                1
            } else {
                0
            }
        }
        Command::CheckNonRevocation {
            nullifier,
            revocation_root,
            credential_root,
            input_mode,
            proof_mode,
        } => {
            let expected = match input_mode {
                RevocationInputMode::Short | RevocationInputMode::Oversized => {
                    Err(RegistryError::InvalidPublicInputs)
                }
                RevocationInputMode::WrongDomain => Err(RegistryError::InvalidPublicInputs),
                RevocationInputMode::Correct | RevocationInputMode::WrongRoot => {
                    if model.revocation_root.is_none() {
                        Err(RegistryError::NotInitialized)
                    } else if Some(slot(revocation_root)) != model.revocation_root
                        || input_mode == RevocationInputMode::WrongRoot
                    {
                        Err(RegistryError::InvalidPublicInputs)
                    } else {
                        model
                            .require_active_root(credential_root)
                            .and_then(|_| {
                                if model.nullifier_exists(nullifier) {
                                    Err(RegistryError::DuplicateNullifier)
                                } else {
                                    Ok(())
                                }
                            })
                            .and_then(|_| {
                                if model.verifier.is_none() {
                                    Err(RegistryError::VerifierNotSet)
                                } else if proof_mode == ProofMode::Empty {
                                    Err(RegistryError::InvalidProof)
                                } else {
                                    Ok(())
                                }
                            })
                    }
                }
            };

            let mut call_args = args(fixture);
            call_args.push_back(
                revocation_public_inputs(
                    &fixture.env,
                    revocation_root,
                    nullifier,
                    credential_root,
                    input_mode,
                )
                .into_val(&fixture.env),
            );
            call_args.push_back(proof_bytes(&fixture.env, proof_mode).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "check_non_revocation", call_args),
                expected,
                "check_non_revocation",
            )?;
            if expected.is_ok() {
                model.nullifiers.push(slot(nullifier));
                1
            } else {
                0
            }
        }
        Command::Reinit { admin } => {
            let expected = Err(RegistryError::AlreadyInitialized);

            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));

            compare_unit(invoke_unit(fixture, "init", call_args), expected, "init")?;
            0
        }
        Command::UpgradeStorage { admin } => {
            let expected = model.require_admin(admin);
            let mut call_args = args(fixture);
            call_args.push_back(fixture.actor(admin).into_val(&fixture.env));

            compare_unit(
                invoke_unit(fixture, "upgrade_storage", call_args),
                expected,
                "upgrade_storage",
            )?;
            if expected.is_ok() {
                let target_version = 1;
                if model.schema_version < target_version {
                    model.schema_version = target_version;
                }
                1
            } else {
                0
            }
        }
        Command::Abort { kind } => {
            match kind {
                AbortKind::CancelledBeforeSubmit
                | AbortKind::TimedOutBeforeSubmit
                | AbortKind::PartialClientWrite => {}
            }
            0
        }
    };

    assert_budget(fixture, &format!("{command:?}"))?;
    assert_events(fixture, expected_events, &format!("{command:?}"))?;
    assert_storage_matches_model(fixture, model)
}

fn assert_budget(fixture: &Fixture, label: &str) -> CheckResult {
    let budget = fixture.env.cost_estimate().budget();
    let cpu = budget.cpu_instruction_cost();
    let mem = budget.memory_bytes_cost();
    if cpu > MAX_FUZZ_CPU {
        return Err(format!(
            "{label} exceeded fuzz CPU bound: {cpu} > {MAX_FUZZ_CPU}"
        ));
    }
    if mem > MAX_FUZZ_MEM {
        return Err(format!(
            "{label} exceeded fuzz memory bound: {mem} > {MAX_FUZZ_MEM}"
        ));
    }
    Ok(())
}

fn assert_events(fixture: &Fixture, expected_events: usize, label: &str) -> CheckResult {
    let actual_events = fixture.env.events().all().events().len();
    if actual_events != expected_events {
        return Err(format!(
            "{label} emitted {actual_events} event(s); expected {expected_events}"
        ));
    }
    Ok(())
}

fn assert_storage_matches_model(fixture: &Fixture, model: &Model) -> CheckResult {
    let client = fixture.client();

    if client.get_proof_ttl() != model.proof_ttl {
        return Err(format!(
            "proof TTL mismatch: contract={} model={}",
            client.get_proof_ttl(),
            model.proof_ttl
        ));
    }

    let expected_verifier = model.verifier.map(|verifier| fixture.verifier(verifier));
    if client.get_verifier() != expected_verifier {
        return Err("verifier storage mismatch".into());
    }

    let expected_revocation_root = model
        .revocation_root
        .map(|root| key(&fixture.env, HashDomain::RevocationRoot, root));
    if client.get_revocation_root() != expected_revocation_root {
        return Err("revocation root storage mismatch".into());
    }

    for proof in 0..KEY_POOL {
        let proof_id = key(&fixture.env, HashDomain::Proof, proof);
        match (client.get_proof(&proof_id), model.find_proof(proof)) {
            (Some(actual), Some(expected)) => {
                assert_record_matches(fixture, &actual, expected, "get_proof")?;
                let status = client.get_proof_status(&proof_id);
                let expected_status = model.expected_status(expected);
                if status != expected_status {
                    return Err(format!(
                        "status mismatch for proof slot {proof}: {status:?} != {expected_status:?}"
                    ));
                }
            }
            (None, None) => {
                let status = client.get_proof_status(&proof_id);
                if status != ProofVerificationStatus::NotFound {
                    return Err(format!(
                        "unknown proof slot {proof} returned status {status:?}"
                    ));
                }
            }
            (Some(_), None) => {
                return Err(format!("contract stored unexpected proof slot {proof}"));
            }
            (None, Some(_)) => {
                return Err(format!("contract missing expected proof slot {proof}"));
            }
        }
    }

    for video in 0..KEY_POOL {
        let video_hash = key(&fixture.env, HashDomain::Video, video);
        match (client.get_by_video(&video_hash), model.find_by_video(video)) {
            (Some(actual), Some(expected)) => {
                assert_record_matches(fixture, &actual, expected, "get_by_video")?;
            }
            (None, None) => {}
            (Some(_), None) => {
                return Err(format!("contract stored unexpected video slot {video}"));
            }
            (None, Some(_)) => {
                return Err(format!("contract missing expected video slot {video}"));
            }
        }
    }

    for nullifier in 0..KEY_POOL {
        let actual = client.has_nullifier(&key(&fixture.env, HashDomain::Nullifier, nullifier));
        let expected = model.nullifier_exists(nullifier);
        if actual != expected {
            return Err(format!(
                "nullifier slot {nullifier} mismatch: contract={actual} model={expected}"
            ));
        }
    }

    for root in 0..KEY_POOL {
        let actual =
            client.get_credential_root(&key(&fixture.env, HashDomain::CredentialRoot, root));
        match (actual, model.credential_roots[root as usize]) {
            (None, RootState::Missing) => {}
            (Some(record), RootState::Active) if record.active => {
                assert_credential_root_record_matches(fixture, model, root, &record)?;
            }
            (Some(record), RootState::Revoked) if !record.active => {
                assert_credential_root_record_matches(fixture, model, root, &record)?;
            }
            (None, expected) => {
                return Err(format!(
                    "credential root slot {root} missing; model={expected:?}"
                ));
            }
            (Some(record), expected) => {
                return Err(format!(
                    "credential root slot {root} active={} model={expected:?}",
                    record.active
                ));
            }
        }
    }

    for actor in ACTORS {
        let actual = client.get_issuer(&fixture.actor(actor));
        match (actual, model.issuers[actor.index()]) {
            (None, IssuerState::Missing) => {}
            (Some(record), IssuerState::Active) if record.active => {
                assert_issuer_record_matches(fixture, model, actor, &record)?;
            }
            (Some(record), IssuerState::Revoked) if !record.active => {
                assert_issuer_record_matches(fixture, model, actor, &record)?;
            }
            (None, expected) => {
                return Err(format!("issuer {actor:?} missing; model={expected:?}"));
            }
            (Some(record), expected) => {
                return Err(format!(
                    "issuer {actor:?} active={} model={expected:?}",
                    record.active
                ));
            }
        }
    }

    Ok(())
}

fn assert_credential_root_record_matches(
    fixture: &Fixture,
    model: &Model,
    root: u8,
    record: &CredentialRootRecord,
) -> CheckResult {
    let root = slot(root);
    if record.metadata_hash
        != key(
            &fixture.env,
            HashDomain::Metadata,
            model.credential_root_metadata[root as usize],
        )
    {
        return Err(format!("credential root slot {root} metadata mismatch"));
    }
    if record.issued_at != model.credential_root_issued_at[root as usize] {
        return Err(format!(
            "credential root slot {root} issued_at mismatch: contract={} model={}",
            record.issued_at, model.credential_root_issued_at[root as usize]
        ));
    }
    Ok(())
}

fn assert_issuer_record_matches(
    fixture: &Fixture,
    model: &Model,
    actor: ActorId,
    record: &IssuerRecord,
) -> CheckResult {
    if record.metadata_hash
        != key(
            &fixture.env,
            HashDomain::Metadata,
            model.issuer_metadata[actor.index()],
        )
    {
        return Err(format!("issuer {actor:?} metadata mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0xA5A5_A5A5_5A5A_5A5A,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn pick(&mut self, upper: u8) -> u8 {
        self.byte() % upper
    }
}

fn generate_commands(seed: u64, steps: usize) -> StdVec<Command> {
    let mut rng = XorShift64::new(seed);
    let mut commands = StdVec::new();
    for _ in 0..steps {
        commands.push(generate_command(&mut rng));
    }
    commands
}

fn generate_command(rng: &mut XorShift64) -> Command {
    match rng.pick(100) {
        0..=13 => Command::RegisterSource {
            source: actor_from(rng.byte()),
            proof: rng.byte(),
            video: rng.byte(),
            metadata: rng.byte(),
        },
        14..=27 => Command::RegisterSeal {
            issuer: actor_from(rng.byte()),
            proof: rng.byte(),
            video: rng.byte(),
            metadata: rng.byte(),
        },
        28..=39 => Command::RegisterAnonymous {
            proof: rng.byte(),
            video: rng.byte(),
            metadata: rng.byte(),
            nullifier: rng.byte(),
            credential_root: rng.byte(),
            proof_mode: proof_mode_from(rng.byte()),
        },
        40..=51 => Command::RegisterAnonymousVerified {
            proof: rng.byte(),
            video: rng.byte(),
            metadata: rng.byte(),
            nullifier: rng.byte(),
            credential_root: rng.byte(),
            input_mode: silent_input_mode_from(rng.byte()),
            proof_mode: proof_mode_from(rng.byte()),
        },
        52..=58 => Command::RevokeProof {
            admin: actor_from(rng.byte()),
            proof: rng.byte(),
        },
        59..=64 => Command::AddIssuer {
            admin: actor_from(rng.byte()),
            issuer: actor_from(rng.byte()),
            metadata: rng.byte(),
        },
        65..=68 => Command::RevokeIssuer {
            admin: actor_from(rng.byte()),
            issuer: actor_from(rng.byte()),
        },
        69..=73 => Command::AddCredentialRoot {
            admin: actor_from(rng.byte()),
            root: rng.byte(),
            metadata: rng.byte(),
        },
        74..=76 => Command::RevokeCredentialRoot {
            admin: actor_from(rng.byte()),
            root: rng.byte(),
        },
        77..=80 => Command::SetVerifier {
            admin: actor_from(rng.byte()),
            verifier: rng.byte(),
        },
        81..=83 => Command::SetProofTtl {
            admin: actor_from(rng.byte()),
            ttl: ttl_from(rng.byte()),
        },
        84..=86 => Command::AdvanceTime {
            delta: delta_from(rng.byte()),
        },
        87..=88 => Command::ProposeAdmin {
            admin: actor_from(rng.byte()),
            pending_admin: actor_from(rng.byte()),
        },
        89 => Command::CancelAdminTransfer {
            admin: actor_from(rng.byte()),
        },
        90 => Command::AcceptAdmin {
            pending_admin: actor_from(rng.byte()),
        },
        91..=93 => Command::SetRevocationRoot {
            admin: actor_from(rng.byte()),
            root: rng.byte(),
        },
        94..=97 => Command::CheckNonRevocation {
            nullifier: rng.byte(),
            revocation_root: rng.byte(),
            credential_root: rng.byte(),
            input_mode: revocation_input_mode_from(rng.byte()),
            proof_mode: proof_mode_from(rng.byte()),
        },
        98 => Command::Reinit {
            admin: actor_from(rng.byte()),
        },
        99 => Command::UpgradeStorage {
            admin: actor_from(rng.byte()),
        },
        _ => Command::Abort {
            kind: match rng.pick(3) {
                0 => AbortKind::CancelledBeforeSubmit,
                1 => AbortKind::TimedOutBeforeSubmit,
                _ => AbortKind::PartialClientWrite,
            },
        },
    }
}

fn run_sequence(commands: &[Command]) -> CheckResult {
    let fixture = Fixture::new();
    let mut model = Model::new();

    assert_storage_matches_model(&fixture, &model)?;

    for (index, command) in commands.iter().copied().enumerate() {
        apply_command(&fixture, &mut model, command)
            .map_err(|error| format!("step {index} {command:?}: {error}"))?;
    }

    Ok(())
}

fn run_case(name: &str, seed: u64, commands: StdVec<Command>) {
    if let Err(error) = run_sequence(&commands) {
        let (shrunk, shrunk_error) = shrink_commands(&commands);
        panic!(
            "registry state-machine fuzz failed\ncase={name}\nseed=0x{seed:016x}\nerror={error}\nshrunk_error={shrunk_error}\nshrunk_commands=\n{}",
            render_commands(&shrunk)
        );
    }
}

fn shrink_commands(commands: &[Command]) -> (StdVec<Command>, String) {
    let mut candidate = commands.to_vec();
    let mut last_error = run_sequence(&candidate)
        .err()
        .unwrap_or_else(|| "sequence unexpectedly passed during shrink".into());

    let mut chunk = candidate.len().max(1) / 2;
    while chunk > 0 {
        let mut index = 0;
        let mut removed = false;
        while index + chunk <= candidate.len() {
            let mut trial = candidate.clone();
            trial.drain(index..index + chunk);
            if let Err(error) = run_sequence(&trial) {
                candidate = trial;
                last_error = error;
                removed = true;
            } else {
                index += 1;
            }
        }
        if !removed {
            chunk /= 2;
        }
    }

    for index in 0..candidate.len() {
        for simpler in simpler_commands(candidate[index]) {
            let mut trial = candidate.clone();
            trial[index] = simpler;
            if let Err(error) = run_sequence(&trial) {
                candidate = trial;
                last_error = error;
                break;
            }
        }
    }

    (candidate, last_error)
}

fn simpler_commands(command: Command) -> StdVec<Command> {
    let mut variants = StdVec::new();
    variants.push(Command::Abort {
        kind: AbortKind::CancelledBeforeSubmit,
    });

    match command {
        Command::RegisterSource {
            source,
            proof,
            video,
            metadata,
        } => {
            if source != ActorId::SourceA {
                variants.push(Command::RegisterSource {
                    source: ActorId::SourceA,
                    proof,
                    video,
                    metadata,
                });
            }
            variants.push(Command::RegisterSource {
                source,
                proof: 0,
                video,
                metadata,
            });
            variants.push(Command::RegisterSource {
                source,
                proof,
                video: 0,
                metadata,
            });
        }
        Command::RegisterSeal {
            issuer,
            proof,
            video,
            metadata,
        } => {
            if issuer != ActorId::IssuerA {
                variants.push(Command::RegisterSeal {
                    issuer: ActorId::IssuerA,
                    proof,
                    video,
                    metadata,
                });
            }
            variants.push(Command::RegisterSeal {
                issuer,
                proof: 0,
                video,
                metadata,
            });
            variants.push(Command::RegisterSeal {
                issuer,
                proof,
                video: 0,
                metadata,
            });
        }
        Command::RegisterAnonymous {
            proof,
            video,
            metadata,
            nullifier,
            credential_root,
            proof_mode,
        } => {
            variants.push(Command::RegisterAnonymous {
                proof: 0,
                video,
                metadata,
                nullifier,
                credential_root,
                proof_mode,
            });
            variants.push(Command::RegisterAnonymous {
                proof,
                video: 0,
                metadata,
                nullifier,
                credential_root,
                proof_mode,
            });
            variants.push(Command::RegisterAnonymous {
                proof,
                video,
                metadata,
                nullifier: 0,
                credential_root,
                proof_mode,
            });
            variants.push(Command::RegisterAnonymous {
                proof,
                video,
                metadata,
                nullifier,
                credential_root: 0,
                proof_mode,
            });
        }
        Command::RegisterAnonymousVerified {
            proof,
            video,
            metadata,
            nullifier,
            credential_root,
            input_mode,
            proof_mode,
        } => {
            variants.push(Command::RegisterAnonymousVerified {
                proof: 0,
                video,
                metadata,
                nullifier,
                credential_root,
                input_mode,
                proof_mode,
            });
            variants.push(Command::RegisterAnonymousVerified {
                proof,
                video: 0,
                metadata,
                nullifier,
                credential_root,
                input_mode,
                proof_mode,
            });
            variants.push(Command::RegisterAnonymousVerified {
                proof,
                video,
                metadata,
                nullifier: 0,
                credential_root,
                input_mode,
                proof_mode,
            });
        }
        Command::SetProofTtl { admin, ttl } if ttl != 0 => {
            variants.push(Command::SetProofTtl { admin, ttl: 0 });
        }
        Command::AdvanceTime { delta } if delta != 0 => {
            variants.push(Command::AdvanceTime { delta: 0 });
        }
        Command::CheckNonRevocation {
            nullifier,
            revocation_root,
            credential_root,
            input_mode,
            proof_mode,
        } => {
            variants.push(Command::CheckNonRevocation {
                nullifier: 0,
                revocation_root,
                credential_root,
                input_mode,
                proof_mode,
            });
            variants.push(Command::CheckNonRevocation {
                nullifier,
                revocation_root: 0,
                credential_root,
                input_mode,
                proof_mode,
            });
            variants.push(Command::CheckNonRevocation {
                nullifier,
                revocation_root,
                credential_root: 0,
                input_mode,
                proof_mode,
            });
        }
        _ => {}
    }

    variants
}

fn render_commands(commands: &[Command]) -> String {
    let mut output = String::new();
    for (index, command) in commands.iter().enumerate() {
        output.push_str(&format!("{index:02}: {command:?}\n"));
    }
    output
}

fn parse_seed(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

#[test]
fn registry_state_machine_curated_corpus() {
    run_case(
        "duplicate_recovery",
        0x93_C0A0_0000_0001,
        std::vec![
            Command::SetVerifier {
                admin: ActorId::Admin0,
                verifier: 0,
            },
            Command::RegisterSource {
                source: ActorId::SourceA,
                proof: 1,
                video: 1,
                metadata: 1,
            },
            Command::RegisterSource {
                source: ActorId::SourceA,
                proof: 1,
                video: 2,
                metadata: 2,
            },
            Command::RegisterSeal {
                issuer: ActorId::IssuerA,
                proof: 2,
                video: 1,
                metadata: 3,
            },
            Command::RegisterSource {
                source: ActorId::SourceB,
                proof: 3,
                video: 3,
                metadata: 3,
            },
            Command::RevokeProof {
                admin: ActorId::Admin0,
                proof: 1,
            },
        ],
    );

    run_case(
        "anonymous_verified_partial_failures",
        0x93_C0A0_0000_0002,
        std::vec![
            Command::RegisterAnonymousVerified {
                proof: 2,
                video: 2,
                metadata: 2,
                nullifier: 2,
                credential_root: 0,
                input_mode: SilentInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
            Command::SetVerifier {
                admin: ActorId::Admin0,
                verifier: 1,
            },
            Command::RegisterAnonymousVerified {
                proof: 2,
                video: 2,
                metadata: 2,
                nullifier: 2,
                credential_root: 0,
                input_mode: SilentInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
            Command::RegisterAnonymousVerified {
                proof: 4,
                video: 4,
                metadata: 4,
                nullifier: 2,
                credential_root: 0,
                input_mode: SilentInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
            Command::RegisterAnonymousVerified {
                proof: 5,
                video: 5,
                metadata: 5,
                nullifier: 5,
                credential_root: 0,
                input_mode: SilentInputMode::Oversized,
                proof_mode: ProofMode::Oversized,
            },
            Command::RegisterAnonymousVerified {
                proof: 6,
                video: 6,
                metadata: 6,
                nullifier: 6,
                credential_root: 0,
                input_mode: SilentInputMode::WrongVideo,
                proof_mode: ProofMode::Valid,
            },
        ],
    );

    run_case(
        "admin_issuer_transfer",
        0x93_C0A0_0000_0003,
        std::vec![
            Command::AddIssuer {
                admin: ActorId::SourceA,
                issuer: ActorId::IssuerB,
                metadata: 2,
            },
            Command::AddIssuer {
                admin: ActorId::Admin0,
                issuer: ActorId::IssuerB,
                metadata: 2,
            },
            Command::RevokeIssuer {
                admin: ActorId::Admin0,
                issuer: ActorId::IssuerB,
            },
            Command::RegisterSeal {
                issuer: ActorId::IssuerB,
                proof: 2,
                video: 2,
                metadata: 2,
            },
            Command::AddIssuer {
                admin: ActorId::Admin0,
                issuer: ActorId::IssuerB,
                metadata: 3,
            },
            Command::RegisterSeal {
                issuer: ActorId::IssuerB,
                proof: 2,
                video: 2,
                metadata: 2,
            },
            Command::ProposeAdmin {
                admin: ActorId::Admin0,
                pending_admin: ActorId::PendingA,
            },
            Command::AcceptAdmin {
                pending_admin: ActorId::PendingB,
            },
            Command::AcceptAdmin {
                pending_admin: ActorId::PendingA,
            },
            Command::AddCredentialRoot {
                admin: ActorId::Admin0,
                root: 2,
                metadata: 2,
            },
            Command::AddCredentialRoot {
                admin: ActorId::PendingA,
                root: 2,
                metadata: 2,
            },
            Command::CancelAdminTransfer {
                admin: ActorId::PendingA,
            },
        ],
    );

    run_case(
        "revocation_domain_replay",
        0x93_C0A0_0000_0004,
        std::vec![
            Command::SetVerifier {
                admin: ActorId::Admin0,
                verifier: 0,
            },
            Command::CheckNonRevocation {
                nullifier: 3,
                revocation_root: 0,
                credential_root: 0,
                input_mode: RevocationInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
            Command::SetRevocationRoot {
                admin: ActorId::Admin0,
                root: 1,
            },
            Command::CheckNonRevocation {
                nullifier: 3,
                revocation_root: 1,
                credential_root: 0,
                input_mode: RevocationInputMode::WrongDomain,
                proof_mode: ProofMode::Valid,
            },
            Command::CheckNonRevocation {
                nullifier: 3,
                revocation_root: 1,
                credential_root: 0,
                input_mode: RevocationInputMode::WrongRoot,
                proof_mode: ProofMode::Valid,
            },
            Command::CheckNonRevocation {
                nullifier: 3,
                revocation_root: 1,
                credential_root: 0,
                input_mode: RevocationInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
            Command::CheckNonRevocation {
                nullifier: 3,
                revocation_root: 1,
                credential_root: 0,
                input_mode: RevocationInputMode::Correct,
                proof_mode: ProofMode::Valid,
            },
        ],
    );

    run_case(
        "timeouts_cancellations_and_ttl_recovery",
        0x93_C0A0_0000_0005,
        std::vec![
            Command::Abort {
                kind: AbortKind::CancelledBeforeSubmit,
            },
            Command::Abort {
                kind: AbortKind::TimedOutBeforeSubmit,
            },
            Command::Abort {
                kind: AbortKind::PartialClientWrite,
            },
            Command::SetProofTtl {
                admin: ActorId::Admin0,
                ttl: 1,
            },
            Command::RegisterSource {
                source: ActorId::SourceA,
                proof: 7,
                video: 7,
                metadata: 7,
            },
            Command::AdvanceTime { delta: 2 },
            Command::RevokeProof {
                admin: ActorId::Admin0,
                proof: 7,
            },
        ],
    );
}

#[test]
fn registry_state_machine_generated_seed_corpus() {
    for seed in REGRESSION_SEEDS {
        run_case(
            "generated_seed_corpus",
            *seed,
            generate_commands(*seed, GENERATED_STEPS),
        );
    }
}

#[test]
fn registry_state_machine_optional_local_fuzz() {
    let runs = std::env::var("HARPOCRATES_REGISTRY_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_LOCAL_FUZZ_RUNS);
    if runs == 0 {
        return;
    }

    let base_seed = std::env::var("HARPOCRATES_REGISTRY_FUZZ_SEED")
        .ok()
        .and_then(|value| parse_seed(&value))
        .unwrap_or(0x93_0000_0000_0000);

    for index in 0..runs {
        let seed = base_seed.wrapping_add(index as u64);
        run_case(
            "optional_local_fuzz",
            seed,
            generate_commands(seed, GENERATED_STEPS),
        );
    }
}
