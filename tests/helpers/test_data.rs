use rand::RngCore;

pub struct TestData {
    pub plaintext: Vec<u8>,
    pub size: usize,
}

impl TestData {
    pub fn random(size: usize) -> Self {
        let mut data = vec![0u8; size];
        rand::rng().fill_bytes(&mut data);
        Self { plaintext: data, size }
    }

    pub fn zeros(size: usize) -> Self {
        Self { plaintext: vec![0u8; size], size }
    }

    pub fn text(content: &str) -> Self {
        let plaintext = content.as_bytes().to_vec();
        let size = plaintext.len();
        Self { plaintext, size }
    }

    pub fn large_mb(mb: usize) -> Self {
        Self::random(mb * 1024 * 1024)
    }
}
