#![no_std]

//! # Ancore Account Contract
//!
//! Core smart account contract implementing account abstraction for Stellar/Soroban.
//!
//! ## Security
//! This contract is security-critical and must be audited before mainnet deployment.
//!
//! ## Features
//! - Signature validation
//! - Session key support
//! - Upgradeable via proxy pattern
//! - Multi-signature support
//!
//! ## Events
//! This contract emits events for all state-changing operations to enable off-chain tracking:
//! - `initialized`: Emitted when the account is initialized with the owner address
//! - `executed`: Emitted when a transaction is executed with to, function, and nonce
//! - `session_key_added`: Emitted when a session key is added with public_key and expires_at
//! - `session_key_revoked`: Emitted when a session key is revoked with public_key

use soroban_sdk::{
    contract, contractimpl, contracterror, contracttype, Address, BytesN, Env, Vec,
};

/// Contract error types for structured error handling
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    /// Account is already initialized
    AlreadyInitialized = 1,
    /// Account is not initialized
    NotInitialized = 2,
    /// Caller is not authorized
    Unauthorized = 3,
    /// Invalid nonce provided
    InvalidNonce = 4,
    /// Session key not found
    SessionKeyNotFound = 5,
    /// Session key has expired
    SessionKeyExpired = 6,
    /// Insufficient permissions
    InsufficientPermission = 7,
}

/// Event topic naming convention
mod events {
    use soroban_sdk::{Env, Symbol};

    /// Event emitted when the account is initialized.
    /// Data: (owner: Address)
    pub fn initialized(env: &Env) -> Symbol {
        Symbol::new(env, "initialized")
    }

    /// Event emitted when a transaction is executed.
    /// Data: (to: Address, function: Symbol, nonce: u64)
    pub fn executed(env: &Env) -> Symbol {
        Symbol::new(env, "executed")
    }

    /// Event emitted when a session key is added.
    /// Data: (public_key: BytesN<32>, expires_at: u64)
    pub fn session_key_added(env: &Env) -> Symbol {
        Symbol::new(env, "session_key_added")
    }

    /// Event emitted when a session key is revoked.
    /// Data: (public_key: BytesN<32>)
    pub fn session_key_revoked(env: &Env) -> Symbol {
        Symbol::new(env, "session_key_revoked")
    }
}

#[contracttype]
#[derive(Clone)]
pub struct SessionKey {
    pub public_key: BytesN<32>,
    pub expires_at: u64,
    pub permissions: Vec<u32>,
}

#[contracttype]
pub enum DataKey {
    Owner,
    Nonce,
    SessionKey(BytesN<32>),
}

#[contract]
pub struct AncoreAccount;

#[contractimpl]
impl AncoreAccount {
    /// Initialize the account with an owner
    pub fn initialize(env: Env, owner: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Owner) {
            return Err(ContractError::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage().instance().set(&DataKey::Nonce, &0u64);

        // Emit initialized event
        env.events().publish((events::initialized(&env),), owner);

        Ok(())
    }

    /// Get the account owner
    pub fn get_owner(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Owner)
            .ok_or(ContractError::NotInitialized)
    }

    /// Get the current nonce
    pub fn get_nonce(env: Env) -> Result<u64, ContractError> {
        Ok(env
            .storage()
            .instance()
            .get(&DataKey::Nonce)
            .unwrap_or(0))
    }

    /// Execute a transaction with nonce replay-protection and dual auth paths.
    ///
    /// # Auth paths
    /// - **Owner path**: `caller` == stored owner → `caller.require_auth()` is sufficient.
    /// - **Session-key path**: `caller` != owner →
    ///     1. `session_key` must be `Some(public_key)` that was previously registered.
    ///     2. The session key must not be expired (`expires_at > current ledger timestamp`).
    ///     3. The session key's `permissions` list must contain `required_permission`.
    ///     4. `caller.require_auth()` is still called so Soroban validates the caller's
    ///        signature over this invocation.
    ///
    /// # Nonce
    /// `expected_nonce` must equal the current nonce stored in the contract.
    /// The nonce is incremented **after** all checks pass, preventing replays.
    ///
    /// # Parameters
    /// - `caller`              – Address of the entity authorising the call (owner or session-key holder).
    /// - `to`                  – Target contract address.
    /// - `function`            – Name of the function to invoke on `to`.
    /// - `_args`               – Arguments forwarded to the cross-contract call (reserved; not yet executed).
    /// - `expected_nonce`      – Caller's view of the current nonce; must match exactly.
    /// - `required_permission` – Permission code the session key must carry (ignored for owner).
    ///
    /// # Errors
    /// - [`ContractError::NotInitialized`]        – Contract has no owner yet.
    /// - [`ContractError::InvalidNonce`]           – `expected_nonce` does not match stored nonce.
    /// - [`ContractError::SessionKeyNotFound`]     – No session key exists for the supplied public key.
    /// - [`ContractError::SessionKeyExpired`]      – Session key's `expires_at` ≤ current ledger timestamp.
    /// - [`ContractError::InsufficientPermission`] – Session key does not carry `required_permission`.
    pub fn execute(
        env: Env,
        caller: Address,
        to: Address,
        function: soroban_sdk::Symbol,
        _args: Vec<soroban_sdk::Val>,
        session_key: Option<BytesN<32>>,
        expected_nonce: u64,
        required_permission: u32,
    ) -> Result<bool, ContractError> {
        let owner = Self::get_owner(env.clone())?;

        // ── Nonce check (before any auth so we fail fast on replays) ─────────
        let current_nonce: u64 = Self::get_nonce(env.clone())?;
        if current_nonce != expected_nonce {
            return Err(ContractError::InvalidNonce);
        }

        // ── Auth path selection ───────────────────────────────────────────────
        if caller == owner {
            // Owner path — standard Soroban auth; no session-key checks needed.
            caller.require_auth();
        } else {
            // Session-key path — caller must present the public key they registered.
            let pk = session_key.ok_or(ContractError::SessionKeyNotFound)?;

            let sk: SessionKey = env
                .storage()
                .persistent()
                .get(&DataKey::SessionKey(pk))
                .ok_or(ContractError::SessionKeyNotFound)?;

            // Expiry: expires_at must be strictly greater than the current ledger timestamp.
            if sk.expires_at <= env.ledger().timestamp() {
                return Err(ContractError::SessionKeyExpired);
            }

            // Permission: the session key's permission list must contain required_permission.
            if !sk.permissions.contains(&required_permission) {
                return Err(ContractError::InsufficientPermission);
            }

            // Validate the caller's cryptographic signature over this invocation.
            caller.require_auth();
        }

        // ── Increment nonce ───────────────────────────────────────────────────
        env.storage()
            .instance()
            .set(&DataKey::Nonce, &(current_nonce + 1));

        // ── Emit executed event ───────────────────────────────────────────────
        env.events()
            .publish((events::executed(&env),), (to, function, current_nonce));

        Ok(true)
    }

    /// Add a session key
    pub fn add_session_key(
        env: Env,
        public_key: BytesN<32>,
        expires_at: u64,
        permissions: Vec<u32>,
    ) -> Result<(), ContractError> {
        let owner = Self::get_owner(env.clone())?;
        owner.require_auth();

        let session_key = SessionKey {
            public_key: public_key.clone(),
            expires_at,
            permissions,
        };

        env.storage()
            .persistent()
            .set(&DataKey::SessionKey(public_key.clone()), &session_key);

        // Emit session_key_added event
        env.events()
            .publish((events::session_key_added(&env),), (public_key, expires_at));

        Ok(())
    }

    /// Revoke a session key
    pub fn revoke_session_key(env: Env, public_key: BytesN<32>) -> Result<(), ContractError> {
        let owner = Self::get_owner(env.clone())?;
        owner.require_auth();

        env.storage()
            .persistent()
            .remove(&DataKey::SessionKey(public_key.clone()));

        // Emit session_key_revoked event
        env.events()
            .publish((events::session_key_revoked(&env),), public_key);

        Ok(())
    }

    /// Get a session key
    pub fn get_session_key(env: Env, public_key: BytesN<32>) -> Option<SessionKey> {
        env.storage()
            .persistent()
            .get(&DataKey::SessionKey(public_key))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger},
        Address, Env,
    };

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Convenience: deploy + initialize the contract and return (client, owner).
    fn setup() -> (Env, AncoreAccountClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        // SAFETY: the client borrows from `env`; we keep both alive by returning them together.
        // Using a raw pointer cast is the standard pattern for Soroban test helpers when the
        // lifetime would otherwise force splitting setup across every test.
        let client = AncoreAccountClient::new(&env, &contract_id);
        // We need 'static lifetime for the client in our return type.
        // This is safe because `env` is returned alongside and kept alive.
        // Standard soroban test pattern: use Box::leak or simply re-create per test.
        // Since Soroban clients are cheap to create we just rebuild in each helper instead.
        let owner = Address::generate(&env);
        client.initialize(&owner);
        (env, client, owner)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Existing tests (updated call sites for new execute() signature)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        assert_eq!(client.get_owner(), owner);
        assert_eq!(client.get_nonce(), 0);
    }

    #[test]
    fn test_initialize_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        let events_list = env.events().all();
        assert_eq!(events_list.len(), 1);
        let (_contract, topics, data) = events_list.get_unchecked(0).clone();
        assert_eq!(topics.len(), 1);

        let topic_symbol: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(&env, &topics.get_unchecked(0));
        assert_eq!(topic_symbol, events::initialized(&env));

        let event_owner: Address = soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(event_owner, owner);
    }

    #[test]
    fn test_add_session_key() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[1u8; 32]);
        let expires_at = 1000u64;
        let permissions = Vec::new(&env);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        let session_key = client.get_session_key(&session_pk);
        assert!(session_key.is_some());
    }

    #[test]
    fn test_add_session_key_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[1u8; 32]);
        let expires_at = 1000u64;
        let permissions = Vec::new(&env);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        let events_list = env.events().all();
        assert!(events_list.len() >= 2);
        let (_contract, topics, data) = events_list.get_unchecked(1).clone();
        assert_eq!(topics.len(), 1);

        let topic_symbol: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(&env, &topics.get_unchecked(0));
        assert_eq!(topic_symbol, events::session_key_added(&env));

        let data_tuple: (BytesN<32>, u64) = soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(data_tuple.0, session_pk);
        assert_eq!(data_tuple.1, expires_at);
    }

    #[test]
    fn test_revoke_session_key_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[1u8; 32]);
        let expires_at = 1000u64;
        let permissions = Vec::new(&env);

        client.add_session_key(&session_pk, &expires_at, &permissions);
        client.revoke_session_key(&session_pk);

        let events_list = env.events().all();
        assert!(events_list.len() >= 3);
        let (_contract, topics, data) = events_list.get_unchecked(2).clone();
        assert_eq!(topics.len(), 1);

        let topic_symbol: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(&env, &topics.get_unchecked(0));
        assert_eq!(topic_symbol, events::session_key_revoked(&env));

        let event_pk: BytesN<32> = soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(event_pk, session_pk);
    }

    /// Owner can execute; event is emitted with correct (to, function, nonce=0).
    #[test]
    fn test_execute_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        // Owner path: session_key = None, expected_nonce = 0, required_permission ignored.
        client.execute(&owner, &to, &function, &args, &None, &0u64, &0u32);

        let events_list = env.events().all();
        assert!(events_list.len() >= 2);
        let (_contract, topics, data) = events_list.get_unchecked(1).clone();
        assert_eq!(topics.len(), 1);

        let topic_symbol: soroban_sdk::Symbol =
            soroban_sdk::FromVal::from_val(&env, &topics.get_unchecked(0));
        assert_eq!(topic_symbol, events::executed(&env));

        let data_tuple: (Address, soroban_sdk::Symbol, u64) =
            soroban_sdk::FromVal::from_val(&env, &data);
        assert_eq!(data_tuple.0, to);
        assert_eq!(data_tuple.1, function);
        assert_eq!(data_tuple.2, 0); // nonce before increment
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1)")]
    fn test_double_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);
        client.initialize(&owner); // Should panic with contract error #1
    }

    /// Passing expected_nonce = 1 when current nonce is 0 must be rejected.
    #[test]
    #[should_panic(expected = "Error(Contract, #4)")]
    fn test_execute_rejects_invalid_nonce() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let to = Address::generate(&env);
        let function = soroban_sdk::symbol_short!("transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        // Nonce is 0; passing 1 must panic with InvalidNonce (#4).
        client.execute(&owner, &to, &function, &args, &None, &1u64, &0u32);
    }

    /// Correct nonce is accepted and incremented to 1 afterward.
    #[test]
    fn test_execute_validates_nonce_then_increments() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        assert_eq!(client.get_nonce(), 0);

        env.mock_all_auths();

        let to = Address::generate(&env);
        let function = soroban_sdk::symbol_short!("get_nonce");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        client.execute(&owner, &to, &function, &args, &None, &0u64, &0u32);

        assert_eq!(client.get_nonce(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New tests — session key authorization (Issue requirement)
    // ─────────────────────────────────────────────────────────────────────────

    /// A session key holder with the correct permission and a valid (future) expiry
    /// can authorize execute().
    #[test]
    fn test_execute_with_valid_session_key() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        // Ledger timestamp starts at 0 in tests; use a future expiry.
        let session_pk = BytesN::from_array(&env, &[2u8; 32]);
        let expires_at = 9999u64; // far future
        let required_permission = 42u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(required_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        let caller = Address::generate(&env); // non-owner caller
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        let result = client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &0u64,
            &required_permission,
        );

        assert!(result);
        // Nonce must have incremented.
        assert_eq!(client.get_nonce(), 1);
    }

    /// A session key whose expires_at <= current ledger timestamp is rejected
    /// with SessionKeyExpired (#6).
    #[test]
    #[should_panic(expected = "Error(Contract, #6)")]
    fn test_execute_rejects_expired_session_key() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[3u8; 32]);
        // expires_at = 100; we will advance the ledger past this.
        let expires_at = 100u64;
        let required_permission = 1u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(required_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        // Advance ledger timestamp beyond expires_at.
        env.ledger().with_mut(|l| {
            l.timestamp = 200; // 200 > 100 → expired
        });

        let caller = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &0u64,
            &required_permission,
        );
    }

    /// A session key that does not carry the required permission is rejected
    /// with InsufficientPermission (#7).
    #[test]
    #[should_panic(expected = "Error(Contract, #7)")]
    fn test_execute_rejects_session_key_with_wrong_permission() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[4u8; 32]);
        let expires_at = 9999u64;
        let granted_permission = 10u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(granted_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        let caller = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        // Require permission 99, but the key only carries 10.
        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &0u64,
            &99u32, // not in key's permission list
        );
    }

    /// After revoking a session key, execute() with that key is rejected
    /// with SessionKeyNotFound (#5).
    #[test]
    #[should_panic(expected = "Error(Contract, #5)")]
    fn test_execute_rejects_revoked_session_key() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[5u8; 32]);
        let expires_at = 9999u64;
        let required_permission = 1u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(required_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        // Owner revokes the key.
        client.revoke_session_key(&session_pk);

        let caller = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        // Attempt to use the revoked key — must fail with #5.
        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &0u64,
            &required_permission,
        );
    }

    /// Calling execute() as a non-owner without supplying a session_key (None)
    /// is rejected with SessionKeyNotFound (#5).
    #[test]
    #[should_panic(expected = "Error(Contract, #5)")]
    fn test_execute_non_owner_without_session_key_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let non_owner = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        client.execute(
            &non_owner,
            &to,
            &function,
            &args,
            &None, // no session key supplied
            &0u64,
            &0u32,
        );
    }

    /// A session key with exactly expires_at == ledger timestamp is treated
    /// as expired (boundary condition: strictly greater than is required).
    #[test]
    #[should_panic(expected = "Error(Contract, #6)")]
    fn test_execute_rejects_session_key_at_exact_expiry_boundary() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[6u8; 32]);
        let expires_at = 500u64;
        let required_permission = 1u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(required_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        // Set ledger timestamp exactly equal to expires_at — should still be rejected.
        env.ledger().with_mut(|l| {
            l.timestamp = expires_at;
        });

        let caller = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &0u64,
            &required_permission,
        );
    }

    /// Nonce increments correctly across two consecutive session-key executions.
    #[test]
    fn test_execute_session_key_increments_nonce_consecutively() {
        let env = Env::default();
        let contract_id = env.register_contract(None, AncoreAccount);
        let client = AncoreAccountClient::new(&env, &contract_id);

        let owner = Address::generate(&env);
        client.initialize(&owner);

        env.mock_all_auths();

        let session_pk = BytesN::from_array(&env, &[7u8; 32]);
        let expires_at = 9999u64;
        let required_permission = 5u32;
        let mut permissions = Vec::new(&env);
        permissions.push_back(required_permission);

        client.add_session_key(&session_pk, &expires_at, &permissions);

        let caller = Address::generate(&env);
        let to = Address::generate(&env);
        let function = soroban_sdk::Symbol::new(&env, "transfer");
        let args: Vec<soroban_sdk::Val> = Vec::new(&env);

        assert_eq!(client.get_nonce(), 0);

        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk.clone()),
            &0u64, // first call: expected_nonce = 0
            &required_permission,
        );
        assert_eq!(client.get_nonce(), 1);

        client.execute(
            &caller,
            &to,
            &function,
            &args,
            &Some(session_pk),
            &1u64, // second call: expected_nonce = 1
            &required_permission,
        );
        assert_eq!(client.get_nonce(), 2);
    }
}