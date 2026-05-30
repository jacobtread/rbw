use zeroize::Zeroize as _;

const LEN: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub struct LockedVec {
    data: Box<arrayvec::ArrayVec<u8, LEN>>,
    _lock: Option<region::LockGuard>,
}

impl Default for LockedVec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<_, LEN>::new());
        let lock = match REGION_LOCK_WORKS.get() {
            Some(true) => Some(region::lock(data.as_ptr(), data.capacity()).unwrap()),
            Some(false) => None,
            None => match region::lock(data.as_ptr(), data.capacity()) {
                Ok(lock) => {
                    let _ = REGION_LOCK_WORKS.set(true);
                    Some(lock)
                }
                Err(e) => {
                    if REGION_LOCK_WORKS.set(false).is_ok() {
                        eprintln!("failed to lock memory region: {e}");
                    }
                    None
                }
            },
        };
        Self { data, _lock: lock }
    }
}

impl LockedVec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.data.zeroize();
        self.data.extend(std::iter::repeat_n(0, LEN));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

impl Drop for LockedVec {
    fn drop(&mut self) {
        self.zero();
    }
}

impl Clone for LockedVec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: LockedVec,
}

impl Password {
    pub fn new(password: LockedVec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: LockedVec,
}

impl Keys {
    pub fn new(keys: LockedVec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: LockedVec,
}

impl PasswordHash {
    pub fn new(hash: LockedVec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: LockedVec,
}

impl PrivateKey {
    pub fn new(private_key: LockedVec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}
