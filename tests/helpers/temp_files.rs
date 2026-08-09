use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

pub struct TempTestEnv {
    _dir: TempDir,
    pub_key_path: PathBuf,
    priv_key_path: PathBuf,
}

#[allow(dead_code)]
impl TempTestEnv {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let pub_key_path = dir.path().join("test_pub.pem");
        let priv_key_path = dir.path().join("test_priv.pem");

        Self {
            _dir: dir,
            pub_key_path,
            priv_key_path,
        }
    }

    pub fn file_path(&self, name: &str) -> PathBuf {
        self._dir.path().join(name)
    }

    pub fn create_file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.file_path(name);
        fs::write(&path, data).unwrap();
        path
    }

    pub fn generate_keys_with_passphrase(&self, passphrase: &str) -> (PathBuf, PathBuf) {
        use std::process::Command;

        let binary = env!("CARGO_BIN_EXE_pqenc");

        let output = Command::new(binary)
            .args([
                "generate-keys",
                "--public-key",
                self.pub_key_path.to_str().unwrap(),
                "--private-key",
                self.priv_key_path.to_str().unwrap(),
                "--passphrase",
                passphrase,
            ])
            .output()
            .expect("Failed to generate keys");

        if !output.status.success() {
            panic!(
                "Key generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        (self.pub_key_path.clone(), self.priv_key_path.clone())
    }

    pub fn decrypt_file_with_passphrase(
        &self,
        input: &str,
        output: &str,
        passphrase: &str,
    ) -> Result<(), String> {
        use std::process::Command;

        let binary = env!("CARGO_BIN_EXE_pqenc");

        let result = Command::new(binary)
            .args([
                "decrypt",
                input,
                "--output",
                output,
                "--private-key",
                self.priv_key_path.to_str().unwrap(),
                "--passphrase",
                passphrase,
            ])
            .output()
            .map_err(|e| format!("Failed to run decrypt: {}", e))?;

        if result.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&result.stderr).to_string())
        }
    }
}
