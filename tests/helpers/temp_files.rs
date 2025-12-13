use std::path::PathBuf;
use std::fs;
use std::io::Write;

pub struct TempTestEnv {
    dir: PathBuf,
    pub_key_path: PathBuf,
    priv_key_path: PathBuf,
}

impl TempTestEnv {
    pub fn new() -> Self {
        let unique_id = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir()
            .join(format!("pqenc_test_{}", unique_id));
        fs::create_dir_all(&dir).unwrap();

        let pub_key_path = dir.join("test_pub.pem");
        let priv_key_path = dir.join("test_priv.pem");

        Self { dir, pub_key_path, priv_key_path }
    }

    pub fn file_path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn create_file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.file_path(name);
        fs::write(&path, data).unwrap();
        path
    }

    /// Generate keys using expect script and return paths
    pub fn generate_keys_with_password(&self, password: &str) -> (PathBuf, PathBuf) {
        use std::process::Command;

        let binary = env!("CARGO_BIN_EXE_pqenc");

        // Create expect script
        let script = format!(r#"#!/usr/bin/expect -f
set timeout 10
spawn {} generate-keys --public-key {} --private-key {}
expect "Enter password for private key:"
send "{}\r"
expect "Confirm password:"
send "{}\r"
expect eof
"#, binary, self.pub_key_path.display(), self.priv_key_path.display(), password, password);

        let script_path = self.dir.join("gen_keys.exp");
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

    /// Decrypt file using expect script
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

        let script_path = self.dir.join("decrypt.exp");
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

impl Drop for TempTestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
