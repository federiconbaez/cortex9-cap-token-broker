use crate::domain::{KeyId, RootKey};
use crate::ports::KeyStore;
use std::collections::BTreeMap;

/// In-memory key ring with rotation.
#[derive(Debug, Default)]
pub struct KeyRing {
    keys: BTreeMap<KeyId, RootKey>,
    active: Option<KeyId>,
}

impl KeyRing {
    /// Adds `key` and makes it the active minting key. Previous keys stay
    /// valid for verification until `retire`d.
    pub fn rotate(&mut self, id: KeyId, key: RootKey) {
        self.keys.insert(id.clone(), key);
        self.active = Some(id);
    }

    /// Removes a key; tokens minted under it stop verifying. The active key
    /// cannot be retired (rotate first).
    pub fn retire(&mut self, id: &KeyId) -> bool {
        if self.active.as_ref() == Some(id) {
            return false;
        }
        self.keys.remove(id).is_some()
    }
}

impl KeyStore for KeyRing {
    fn active(&self) -> Option<(KeyId, RootKey)> {
        let id = self.active.clone()?;
        let key = self.keys.get(&id)?.clone();
        Some((id, key))
    }

    fn get(&self, id: &KeyId) -> Option<RootKey> {
        self.keys.get(id).cloned()
    }
}

impl<K: KeyStore + ?Sized> KeyStore for &K {
    fn active(&self) -> Option<(KeyId, RootKey)> {
        (**self).active()
    }
    fn get(&self, id: &KeyId) -> Option<RootKey> {
        (**self).get(id)
    }
}
