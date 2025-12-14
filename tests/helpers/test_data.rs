use rand::RngCore;

#[allow(dead_code)]
pub struct TestData {
    pub plaintext: Vec<u8>,
}

#[allow(dead_code)]
impl TestData {
    pub fn random(size: usize) -> Self {
        let mut data = vec![0u8; size];
        rand::rng().fill_bytes(&mut data);
        Self { plaintext: data }
    }

    pub fn text(content: &str) -> Self {
        let plaintext = content.as_bytes().to_vec();
        Self { plaintext }
    }
}
