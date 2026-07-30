use std::path::PathBuf;
use std::fs;
use std::io::Write;
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

        Self { _dir: dir, pub_key_path, priv_key_path }
    }

    pub fn file_path(&self, name: &str) -> PathBuf {
        self._dir.path().join(name)
    }

    pub fn create_file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.file_path(name);
        fs::write(&path, data).unwrap();
        path
    }

    pub fn generate_keys_with_password(&self, password: &str) -> (PathBuf, PathBuf) {
        use std::process::Command;

        let binary = env!("CARGO_BIN_EXE_pqenc");

        let script = format!(r#"#!/usr/bin/expect -f
set timeout 10
spawn {} generate-keys --public-key {} --private-key {}
expect "Enter password for private key:"
send "{}\r"
expect "Confirm password:"
send "{}\r"
expect eof
lassign [wait] pid spawnid os_error_flag value
exit $value
"#, binary, self.pub_key_path.display(), self.priv_key_path.display(), password, password);

        let script_path = self._dir.path().join("gen_keys.exp");
        let mut file = fs::File::create(&script_path).unwrap();
        file.write_all(script.as_bytes()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let output = Command::new(&script_path)
            .output()
            .expect("Failed to generate keys");

        if !output.status.success() {
            panic!("Key generation failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        (self.pub_key_path.clone(), self.priv_key_path.clone())
    }

    pub fn decrypt_file_with_password(
        &self,
        input: &str,
        output: &str,
        password: &str
    ) -> Result<(), String> {
        use std::process::Command;

        let binary = env!("CARGO_BIN_EXE_pqenc");

        let script = format!(r#"#!/usr/bin/expect -f
set timeout 10
spawn {} decrypt --decrypt {} --output {} --private-key {}
expect "Enter private key password:"
send "{}\r"
expect eof
lassign [wait] pid spawnid os_error_flag value
exit $value
"#, binary, input, output, self.priv_key_path.display(), password);

        let script_path = self._dir.path().join("decrypt.exp");
        let mut file = fs::File::create(&script_path).unwrap();
        file.write_all(script.as_bytes()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let output = Command::new(&script_path).output()
            .map_err(|e| format!("Failed to run decrypt: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}
