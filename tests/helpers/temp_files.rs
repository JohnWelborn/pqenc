use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Points `cmd`'s `HOME` (Unix) and `USERPROFILE` (Windows) at `home`, so a
/// subprocess run with it resolves pqenc's default `~/.pqenc` key location
/// to `home/.pqenc` -- only the platform-relevant variable is ever read by
/// `home_dir()` in src/main.rs, so setting both unconditionally is harmless
/// and keeps tests platform-agnostic. Each invocation gets its own child
/// process, so there's no shared mutable state between tests to coordinate.
#[allow(dead_code)]
pub fn set_fake_home(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home).env("USERPROFILE", home);
}

/// Writes `passphrase` to `dir/passphrase.txt`, sets owner-only permissions
/// on Unix (pqenc's `--passphrase-file` refuses a group/world-readable
/// file), and returns the path.
#[allow(dead_code)]
pub fn write_passphrase_file(dir: &Path, passphrase: &str) -> PathBuf {
    let path = dir.join("passphrase.txt");
    fs::write(&path, passphrase).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

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

    /// Writes `passphrase` to a `--passphrase-file`-ready file inside this
    /// env's own temp dir and returns its path.
    pub fn passphrase_file(&self, passphrase: &str) -> PathBuf {
        write_passphrase_file(self._dir.path(), passphrase)
    }

    pub fn generate_keys_with_passphrase(&self, passphrase: &str) -> (PathBuf, PathBuf) {
        let binary = env!("CARGO_BIN_EXE_pqenc");
        let passphrase_file = write_passphrase_file(self._dir.path(), passphrase);

        let output = Command::new(binary)
            .args([
                "generate-keys",
                "--public-key",
                self.pub_key_path.to_str().unwrap(),
                "--private-key",
                self.priv_key_path.to_str().unwrap(),
                "--passphrase-file",
                passphrase_file.to_str().unwrap(),
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
        let binary = env!("CARGO_BIN_EXE_pqenc");
        let passphrase_file = write_passphrase_file(self._dir.path(), passphrase);

        let result = Command::new(binary)
            .args([
                "decrypt",
                input,
                "--output",
                output,
                "--private-key",
                self.priv_key_path.to_str().unwrap(),
                "--passphrase-file",
                passphrase_file.to_str().unwrap(),
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
