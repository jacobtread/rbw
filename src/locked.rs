use zeroize::Zeroize;

const LEN: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub struct LockedVec {
    data: Box<([u8; LEN], usize)>,
    _lock: Option<region::LockGuard>,
}

// TODO: Think about making the memory lock a hard requirement instead
impl Default for LockedVec {
    fn default() -> Self {
        let data = Box::new(([0u8; LEN], 0));
        let lock = match REGION_LOCK_WORKS.get() {
            Some(true) => Some(region::lock(data.0.as_ptr(), LEN).unwrap()),
            Some(false) => None,
            None => match region::lock(data.0.as_ptr(), LEN) {
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

    pub fn capacity(&self) -> usize {
        LEN
    }

    pub fn len(&self) -> usize {
        self.data.1
    }

    pub fn data(&self) -> &[u8] {
        &self.data.0[0..self.len()]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.data.0[0..len]
    }

    pub fn push(&mut self, el: u8) {
        let len = self.len();

        if len == self.capacity() {
            panic!("Array capacity exceeded");
        }

        self.data.0[len] = el;
        self.data.1 += 1;
    }

    pub fn alloc_all(&mut self) {
        self.truncate(0);
        self.extend(std::iter::repeat_n(0, self.capacity()));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        for el in it {
            self.push(el);
        }
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.1 = usize::min(len, self.len());
        self.data.0[self.data.1..].zeroize();
    }
}

impl Drop for LockedVec {
    fn drop(&mut self) {
        self.data.zeroize()
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
