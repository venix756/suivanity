use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bech32::{Bech32, Hrp};
use bip39::{Language, Mnemonic};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;

type Blake2b256 = Blake2b<U32>;
type HmacSha512 = Hmac<Sha512>;

const SUI_ED25519_FLAG: u8 = 0x00;
const SUI_DERIVATION_PATH: [u32; 5] = [44, 784, 0, 0, 0];

#[derive(Parser, Debug)]
#[command(
    name = "suivanity",
    version,
    about = "Fast vanity address generator for Sui (0x + 64 hex)."
)]
struct Args {
    #[arg(
        long,
        short = 'p',
        alias = "starts-with",
        help = "Prefix to match (hex only, optional 0x). Alias: --starts-with"
    )]
    prefix: Option<String>,

    #[arg(
        long,
        short = 's',
        alias = "ends-with",
        help = "Suffix to match (hex only, optional 0x). Alias: --ends-with"
    )]
    suffix: Option<String>,

    #[arg(
        long,
        value_enum,
        default_value_t = OutputMode::Private,
        help = "Output mode: private (default) or mnemonic"
    )]
    mode: OutputMode,

    #[arg(
        long,
        default_value_t = default_threads(),
        help = "Worker threads (default: number of CPU cores)"
    )]
    threads: usize,

    #[arg(
        long,
        default_value_t = 1,
        help = "Number of matches to find sequentially"
    )]
    count: usize,

    #[arg(
        long,
        default_value_t = false,
        help = "Disable progress logs to stderr"
    )]
    no_progress: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputMode {
    Private,
    Mnemonic,
}

#[derive(Clone, Debug)]
struct AddressPattern {
    prefix: Option<String>,
    suffix: Option<String>,
}

impl AddressPattern {
    fn matches(&self, address_no_prefix: &str) -> bool {
        let prefix_ok = self
            .prefix
            .as_ref()
            .map(|p| address_no_prefix.starts_with(p))
            .unwrap_or(true);

        let suffix_ok = self
            .suffix
            .as_ref()
            .map(|s| address_no_prefix.ends_with(s))
            .unwrap_or(true);

        prefix_ok && suffix_ok
    }
}

#[derive(Clone, Debug)]
struct WalletCandidate {
    address: String,
    private_key: [u8; 32],
    mnemonic: Option<String>,
}

#[derive(Debug)]
struct SearchResult {
    candidate: WalletCandidate,
    attempts: u64,
    elapsed: Duration,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.threads == 0 {
        bail!("--threads must be >= 1");
    }

    if args.count == 0 {
        bail!("--count must be >= 1");
    }

    let pattern = AddressPattern {
        prefix: normalize_pattern(args.prefix.as_deref(), "prefix")?,
        suffix: normalize_pattern(args.suffix.as_deref(), "suffix")?,
    };

    if pattern.prefix.is_none() && pattern.suffix.is_none() {
        bail!(
            "Set at least one matcher: --prefix or --suffix (aliases: --starts-with / --ends-with)."
        );
    }

    for idx in 1..=args.count {
        eprintln!(
            "search #{idx}: mode={:?}, threads={}, prefix={:?}, suffix={:?}",
            args.mode, args.threads, pattern.prefix, pattern.suffix
        );

        let result = find_one(pattern.clone(), args.mode, args.threads, !args.no_progress)?;
        print_result(idx, &result)?;
    }

    Ok(())
}

fn find_one(
    pattern: AddressPattern,
    mode: OutputMode,
    threads: usize,
    show_progress: bool,
) -> Result<SearchResult> {
    let started = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<WalletCandidate>();

    let progress_handle = if show_progress {
        Some(spawn_progress(
            Arc::clone(&found),
            Arc::clone(&attempts),
            started,
        ))
    } else {
        None
    };

    let mut workers = Vec::with_capacity(threads);

    for _ in 0..threads {
        let worker_found = Arc::clone(&found);
        let worker_attempts = Arc::clone(&attempts);
        let worker_tx = tx.clone();
        let worker_pattern = pattern.clone();

        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut local_attempts = 0u64;

            loop {
                if worker_found.load(Ordering::Relaxed) {
                    break;
                }

                let candidate = match generate_candidate(mode, &mut rng) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                local_attempts += 1;

                if worker_pattern.matches(candidate.address.strip_prefix("0x").unwrap_or(&candidate.address)) {
                    worker_attempts.fetch_add(local_attempts, Ordering::Relaxed);

                    if !worker_found.swap(true, Ordering::SeqCst) {
                        let _ = worker_tx.send(candidate);
                    }

                    return;
                }

                if local_attempts >= 1024 {
                    worker_attempts.fetch_add(local_attempts, Ordering::Relaxed);
                    local_attempts = 0;
                }
            }

            if local_attempts > 0 {
                worker_attempts.fetch_add(local_attempts, Ordering::Relaxed);
            }
        });

        workers.push(handle);
    }

    drop(tx);

    let candidate = rx
        .recv()
        .context("all workers exited before finding a match")?;

    found.store(true, Ordering::SeqCst);

    for handle in workers {
        let _ = handle.join();
    }

    if let Some(handle) = progress_handle {
        let _ = handle.join();
    }

    let elapsed = started.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);

    Ok(SearchResult {
        candidate,
        attempts: total_attempts,
        elapsed,
    })
}

fn spawn_progress(
    found: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    started: Instant,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut prev_attempts = 0u64;
        let mut prev_tick = started;

        while !found.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            let now = Instant::now();
            let current = attempts.load(Ordering::Relaxed);
            let delta = current.saturating_sub(prev_attempts);
            let dt = now.duration_since(prev_tick).as_secs_f64().max(0.000_001);
            let rate = delta as f64 / dt;

            eprintln!(
                "attempts={} rate={:.0}/s elapsed={:.1}s",
                current,
                rate,
                now.duration_since(started).as_secs_f64()
            );

            prev_attempts = current;
            prev_tick = now;
        }
    })
}

fn generate_candidate(mode: OutputMode, rng: &mut rand::rngs::ThreadRng) -> Result<WalletCandidate> {
    match mode {
        OutputMode::Private => {
            let mut private_key = [0u8; 32];
            rng.fill_bytes(&mut private_key);

            Ok(WalletCandidate {
                address: sui_address_from_private_key(&private_key),
                private_key,
                mnemonic: None,
            })
        }
        OutputMode::Mnemonic => {
            let mut entropy = [0u8; 16];
            rng.fill_bytes(&mut entropy);

            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .context("failed to build mnemonic from entropy")?;

            let seed = mnemonic.to_seed_normalized("");
            let private_key = derive_ed25519_slip10(&seed, &SUI_DERIVATION_PATH)?;

            Ok(WalletCandidate {
                address: sui_address_from_private_key(&private_key),
                private_key,
                mnemonic: Some(mnemonic.to_string()),
            })
        }
    }
}

fn derive_ed25519_slip10(seed: &[u8], path: &[u32]) -> Result<[u8; 32]> {
    let mut i = hmac_sha512(b"ed25519 seed", seed)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&i[..32]);

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);

    for index in path {
        let hardened = index
            .checked_add(1 << 31)
            .context("derivation index overflow")?;

        let mut data = Vec::with_capacity(1 + 32 + 4);
        data.push(0x00);
        data.extend_from_slice(&key);
        data.extend_from_slice(&hardened.to_be_bytes());

        i = hmac_sha512(&chain_code, &data)?;
        key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);
    }

    Ok(key)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key).context("failed to initialize HMAC")?;
    mac.update(data);

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn sui_address_from_private_key(private_key: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(private_key);
    let public_key = signing_key.verifying_key().to_bytes();

    let mut hasher = Blake2b256::new();
    hasher.update([SUI_ED25519_FLAG]);
    hasher.update(public_key);

    format!("0x{}", hex::encode(hasher.finalize()))
}

fn suiprivkey_from_private_key(private_key: &[u8; 32]) -> Result<String> {
    let mut payload = [0u8; 33];
    payload[0] = SUI_ED25519_FLAG;
    payload[1..].copy_from_slice(private_key);

    let hrp = Hrp::parse("suiprivkey").context("invalid bech32 HRP")?;
    let encoded = bech32::encode::<Bech32>(hrp, &payload).context("failed to encode suiprivkey")?;

    Ok(encoded)
}

fn normalize_pattern(value: Option<&str>, field_name: &str) -> Result<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };

    let lowered = raw.trim().to_ascii_lowercase();
    let normalized = lowered.strip_prefix("0x").unwrap_or(&lowered).to_string();

    if normalized.is_empty() {
        bail!("{field_name} cannot be empty");
    }

    if normalized.len() > 64 {
        bail!("{field_name} cannot be longer than 64 hex chars");
    }

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut invalid = normalized
            .chars()
            .filter(|c| !c.is_ascii_hexdigit())
            .collect::<Vec<char>>();
        invalid.sort_unstable();
        invalid.dedup();
        let invalid_display = invalid
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        bail!(
            "{field_name} must be hex. Allowed symbols: 0 1 2 3 4 5 6 7 8 9 a b c d e f. \
Invalid characters found: {invalid_display}."
        );
    }

    Ok(Some(normalized))
}

fn print_result(index: usize, result: &SearchResult) -> Result<()> {
    let private_hex = hex::encode(result.candidate.private_key);
    let suiprivkey = suiprivkey_from_private_key(&result.candidate.private_key)?;
    let speed = result.attempts as f64 / result.elapsed.as_secs_f64().max(0.000_001);

    println!("match #{index}");
    println!("address: {}", result.candidate.address);
    println!("private_key_hex: {private_hex}");
    println!("suiprivkey: {suiprivkey}");

    if let Some(mnemonic) = &result.candidate.mnemonic {
        println!("mnemonic: {mnemonic}");
    }

    println!("attempts: {}", result.attempts);
    println!("elapsed: {:.3}s", result.elapsed.as_secs_f64());
    println!("speed: {:.0} attempts/s", speed);
    println!();

    Ok(())
}

fn default_threads() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
