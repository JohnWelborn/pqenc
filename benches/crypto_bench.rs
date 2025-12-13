use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::process::Command;
use std::fs;
use std::path::PathBuf;
use std::io::Write;
use std::time::Duration;

fn pqenc_binary() -> String {
    env!("CARGO_BIN_EXE_pqenc").to_string()
}

// Helper to generate keys once for all benchmarks
fn setup_test_keys() -> (PathBuf, PathBuf) {
    let temp_dir = std::env::temp_dir();
    let pub_key = temp_dir.join("bench_pub.pem");
    let priv_key = temp_dir.join("bench_priv.pem");

    // Only generate if they don't exist
    if !pub_key.exists() || !priv_key.exists() {
        let script = format!(r#"#!/usr/bin/expect -f
set timeout 30
spawn {} generate-keys --public-key {} --private-key {}
expect "Enter password for private key:"
send "bench-password\r"
expect "Confirm password:"
send "bench-password\r"
expect eof
"#, pqenc_binary(), pub_key.display(), priv_key.display());

        let script_path = temp_dir.join("gen_bench_keys.exp");
        let mut file = fs::File::create(&script_path).unwrap();
        file.write_all(script.as_bytes()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        Command::new(&script_path)
            .output()
            .expect("Failed to generate benchmark keys");
    }

    (pub_key, priv_key)
}

fn benchmark_encryption_sizes(c: &mut Criterion) {
    let (pub_key, _) = setup_test_keys();
    let temp_dir = std::env::temp_dir();

    let mut group = c.benchmark_group("encryption");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for size in [1024, 64*1024, 256*1024, 1024*1024].iter() {
        let data = vec![0u8; *size];
        let input_path = temp_dir.join(format!("bench_input_{}.bin", size));
        let output_path = temp_dir.join(format!("bench_output_{}.enc", size));
        fs::write(&input_path, &data).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            size,
            |b, _| {
                b.iter(|| {
                    let output = Command::new(pqenc_binary())
                        .args(&["encrypt",
                            "--encrypt", input_path.to_str().unwrap(),
                            "--output", output_path.to_str().unwrap(),
                            "--public-key", pub_key.to_str().unwrap()])
                        .output()
                        .unwrap();

                    black_box(output);
                });
            }
        );
    }

    group.finish();
}

fn benchmark_decryption_sizes(c: &mut Criterion) {
    let (pub_key, priv_key) = setup_test_keys();
    let temp_dir = std::env::temp_dir();

    let mut group = c.benchmark_group("decryption");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for size in [1024, 64*1024, 256*1024, 1024*1024].iter() {
        let data = vec![0u8; *size];
        let input_path = temp_dir.join(format!("bench_dec_input_{}.bin", size));
        let encrypted_path = temp_dir.join(format!("bench_dec_encrypted_{}.enc", size));
        let output_path = temp_dir.join(format!("bench_dec_output_{}.bin", size));

        fs::write(&input_path, &data).unwrap();

        // Encrypt once
        Command::new(pqenc_binary())
            .args(&["encrypt",
                "--encrypt", input_path.to_str().unwrap(),
                "--output", encrypted_path.to_str().unwrap(),
                "--public-key", pub_key.to_str().unwrap()])
            .output()
            .unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            size,
            |b, _| {
                b.iter(|| {
                    let script = format!(r#"#!/usr/bin/expect -f
set timeout 30
spawn {} decrypt --decrypt {} --output {} --private-key {}
expect "Enter private key password:"
send "bench-password\r"
expect eof
"#, pqenc_binary(), encrypted_path.display(), output_path.display(), priv_key.display());

                    let script_path = temp_dir.join(format!("bench_decrypt_{}.exp", size));
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
                        .unwrap();

                    black_box(output);
                });
            }
        );
    }

    group.finish();
}

fn benchmark_key_generation(c: &mut Criterion) {
    let temp_dir = std::env::temp_dir();

    let mut group = c.benchmark_group("key_generation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(22));

    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let pub_key = temp_dir.join(format!("keygen_pub_{}.pem", rand::random::<u32>()));
            let priv_key = temp_dir.join(format!("keygen_priv_{}.pem", rand::random::<u32>()));

            let script = format!(r#"#!/usr/bin/expect -f
set timeout 30
spawn {} generate-keys --public-key {} --private-key {}
expect "Enter password for private key:"
send "bench-password\r"
expect "Confirm password:"
send "bench-password\r"
expect eof
"#, pqenc_binary(), pub_key.display(), priv_key.display());

            let script_path = temp_dir.join(format!("keygen_{}.exp", rand::random::<u32>()));
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
                .unwrap();

            black_box(output);

            // Cleanup
            let _ = fs::remove_file(&pub_key);
            let _ = fs::remove_file(&priv_key);
            let _ = fs::remove_file(&script_path);
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_encryption_sizes, benchmark_decryption_sizes, benchmark_key_generation);
criterion_main!(benches);
