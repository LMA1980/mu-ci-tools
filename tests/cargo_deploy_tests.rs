//! Integration tests for `CargoDeployAdapter`, real `cargo metadata` DAG planning,
//! two-tier licensing gates, `muregist` sparse-index `ETag` polling, and clean-room
//! consumer resolution (`cargo check --tests`) with `crates.io` egress blocked.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mu_ci_tools::adapters::deploy::{
    cargo_index_relative_path, compute_publish_plan, execute_cargo_deploy, load_cargo_metadata,
    verify_workspace_licenses, TIER1_LICENSE_SPDX, TIER2_LICENSE_SPDX,
};
use mu_ci_tools::{
    CargoDeployAdapter, CargoDeployExecutionConfig, CargoDeployParams, DeployError,
    HttpSparseIndexClient, LicensePolicyMode, LicenseTier, SystemCargoRunner, ToolAdapter,
    ToolInvocation,
};

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut w = [0_u32; 64];
        for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, delta) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(delta);
        }
    }

    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

fn write_tier1_license(dir: &Path) {
    fs::write(
        dir.join("LICENSE"),
        "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n\n\
         LGPL-3.0 Linking Exception\n",
    )
    .expect("write Tier-1 LICENSE");
}

fn write_tier2_license(dir: &Path) {
    fs::write(
        dir.join("LICENSE"),
        "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n",
    )
    .expect("write Tier-2 LICENSE");
}

fn write_crate(
    root: &Path,
    rel_dir: &str,
    cargo_toml: &str,
    lib_rs: Option<&str>,
    main_rs: Option<&str>,
) {
    let crate_dir = root.join(rel_dir);
    fs::create_dir_all(crate_dir.join("src")).expect("create src");
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");
    if let Some(lib) = lib_rs {
        fs::write(crate_dir.join("src/lib.rs"), lib).expect("write src/lib.rs");
    }
    if let Some(main) = main_rs {
        fs::write(crate_dir.join("src/main.rs"), main).expect("write src/main.rs");
    }
}

#[derive(Default)]
struct MockRegistryState {
    crates: HashMap<(String, String), Vec<u8>>,
    index_lines: BTreeMap<String, Vec<String>>,
    index_etags: BTreeMap<String, String>,
    publish_sequence: Vec<String>,
    requests: Vec<String>,
}

struct MockMuRegistServer {
    port: u16,
    state: Arc<Mutex<MockRegistryState>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockMuRegistServer {
    fn start(expected_token: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let port = listener.local_addr().expect("local addr").port();
        let state = Arc::new(Mutex::new(MockRegistryState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let state_bg = Arc::clone(&state);
        let shutdown_bg = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            while !shutdown_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_http_connection(stream, port, expected_token, &state_bg);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            state,
            shutdown,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for MockMuRegistServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Option<ParsedHttpRequest> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut temp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
    }

    let header_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut req_parts = request_line.split_whitespace();
    let method = req_parts.next()?.to_string();
    let path = req_parts.next()?.to_string();

    let mut headers = HashMap::new();
    let mut content_len = 0_usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_lower = k.trim().to_ascii_lowercase();
            let v_trimmed = v.trim().to_string();
            if k_lower == "content-length" {
                content_len = v_trimmed.parse::<usize>().unwrap_or(0);
            }
            headers.insert(k_lower, v_trimmed);
        }
    }

    let body_start = header_end + 4;
    while buf.len().saturating_sub(body_start) < content_len {
        let n = stream.read(&mut temp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
    }
    let body_end = (body_start + content_len).min(buf.len());
    Some(ParsedHttpRequest {
        method,
        path,
        headers,
        body: buf[body_start..body_end].to_vec(),
    })
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    etag: Option<&str>,
    body: &[u8],
) {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-cache, must-revalidate\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(tag) = etag {
        head.push_str(&format!("ETag: {tag}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn handle_http_connection(
    mut stream: TcpStream,
    port: u16,
    expected_token: &str,
    state: &Arc<Mutex<MockRegistryState>>,
) {
    let Some(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    }) = read_http_request(&mut stream)
    else {
        return;
    };

    state
        .lock()
        .expect("lock")
        .requests
        .push(format!("{method} {path}"));

    if method == "GET" && (path == "/config.json" || path == "/index/config.json") {
        let cfg = format!(
            "{{\"dl\":\"http://127.0.0.1:{port}/api/v1/crates\",\"api\":\"http://127.0.0.1:{port}\"}}"
        );
        write_http_response(
            &mut stream,
            "200 OK",
            "application/json",
            None,
            cfg.as_bytes(),
        );
        return;
    }

    if method == "PUT" && path == "/api/v1/crates/new" {
        let supplied_auth = headers
            .get("authorization")
            .map(String::as_str)
            .unwrap_or("");
        let stripped = supplied_auth
            .strip_prefix("Bearer ")
            .unwrap_or(supplied_auth);
        if stripped != expected_token {
            write_http_response(
                &mut stream,
                "401 Unauthorized",
                "application/json",
                None,
                br#"{"errors":[{"detail":"unauthorized"}]}"#,
            );
            return;
        }

        if body.len() < 8 {
            write_http_response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                None,
                br#"{"errors":[{"detail":"truncated publish payload"}]}"#,
            );
            return;
        }
        let json_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
        if body.len() < 4 + json_len + 4 {
            write_http_response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                None,
                br#"{"errors":[{"detail":"invalid json length"}]}"#,
            );
            return;
        }
        let meta_bytes = &body[4..4 + json_len];
        let tar_len_pos = 4 + json_len;
        let tar_len = u32::from_le_bytes([
            body[tar_len_pos],
            body[tar_len_pos + 1],
            body[tar_len_pos + 2],
            body[tar_len_pos + 3],
        ]) as usize;
        let tar_start = tar_len_pos + 4;
        if body.len() < tar_start + tar_len {
            write_http_response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                None,
                br#"{"errors":[{"detail":"invalid tarball length"}]}"#,
            );
            return;
        }
        let tarball = body[tar_start..tar_start + tar_len].to_vec();
        let meta: serde_json::Value = match serde_json::from_slice(meta_bytes) {
            Ok(v) => v,
            Err(_) => {
                write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "application/json",
                    None,
                    br#"{"errors":[{"detail":"invalid publish JSON"}]}"#,
                );
                return;
            }
        };

        let name = meta["name"].as_str().unwrap_or("").to_string();
        let vers = meta["vers"].as_str().unwrap_or("").to_string();
        let rel_path = cargo_index_relative_path(&name).expect("valid crate name");
        let cksum = sha256_hex(&tarball);

        let mapped_deps: Vec<serde_json::Value> = meta["deps"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|mut dep| {
                if let Some(obj) = dep.as_object_mut() {
                    if let Some(version_req) = obj.remove("version_req") {
                        obj.insert("req".to_string(), version_req);
                    }
                    obj.insert("yanked".to_string(), serde_json::Value::Bool(false));
                }
                dep
            })
            .collect();

        let index_entry = serde_json::json!({
            "name": name,
            "vers": vers,
            "deps": mapped_deps,
            "cksum": cksum,
            "features": meta["features"].clone(),
            "yanked": false,
        });

        let mut guard = state.lock().expect("lock");
        let key = (name.clone(), vers.clone());
        if guard.crates.contains_key(&key) {
            write_http_response(
                &mut stream,
                "409 Conflict",
                "application/json",
                None,
                br#"{"errors":[{"detail":"crate version already uploaded"}]}"#,
            );
            return;
        }
        guard.crates.insert(key, tarball);
        guard.publish_sequence.push(format!("{name}@{vers}"));
        let lines = guard.index_lines.entry(rel_path.clone()).or_default();
        lines.push(index_entry.to_string());
        let joined = format!("{}\n", lines.join("\n"));
        let etag = format!("\"sha256:{}\"", sha256_hex(joined.as_bytes()));
        guard.index_etags.insert(rel_path, etag);

        write_http_response(
            &mut stream,
            "200 OK",
            "application/json",
            None,
            br#"{"warnings":{"invalid_categories":[],"invalid_badges":[],"other":[]}}"#,
        );
        return;
    }

    if method == "GET" && path.starts_with("/index/") {
        let rel = path.trim_start_matches("/index/");
        let guard = state.lock().expect("lock");
        if let Some(lines) = guard.index_lines.get(rel) {
            let body_str = format!("{}\n", lines.join("\n"));
            let etag = guard.index_etags.get(rel).map(String::as_str);
            if let Some(if_none_match) = headers.get("if-none-match") {
                if etag.is_some_and(|current| current == if_none_match.as_str()) {
                    write_http_response(&mut stream, "304 Not Modified", "text/plain", etag, b"");
                    return;
                }
            }
            write_http_response(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                etag,
                body_str.as_bytes(),
            );
        } else {
            write_http_response(
                &mut stream,
                "404 Not Found",
                "text/plain",
                None,
                b"not found",
            );
        }
        return;
    }

    if method == "GET" && path.starts_with("/api/v1/crates/") && path.ends_with("/download") {
        let trimmed = path
            .trim_start_matches("/api/v1/crates/")
            .trim_end_matches("/download");
        let mut parts = trimmed.split('/');
        if let (Some(name), Some(vers), None) = (parts.next(), parts.next(), parts.next()) {
            let guard = state.lock().expect("lock");
            if let Some(tarball) = guard.crates.get(&(name.to_string(), vers.to_string())) {
                write_http_response(&mut stream, "200 OK", "application/x-tar", None, tarball);
                return;
            }
        }
    }

    write_http_response(
        &mut stream,
        "404 Not Found",
        "text/plain",
        None,
        b"not found",
    );
}

#[test]
fn test_sha256_vector() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn test_real_cargo_metadata_topological_order_and_license_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/ws-app\", \"crates/ws-mid\", \"crates/ws-core\"]\nresolver = \"2\"\n",
    )
    .expect("write workspace Cargo.toml");

    write_crate(
        root,
        "crates/ws-core",
        &format!(
            "[package]\nname = \"ws-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER1_LICENSE_SPDX}\"\n"
        ),
        Some("pub fn value() -> u32 { 42 }\n"),
        None,
    );
    write_tier1_license(&root.join("crates/ws-core"));

    write_crate(
        root,
        "crates/ws-mid",
        &format!(
            "[package]\nname = \"ws-mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER1_LICENSE_SPDX}\"\n\n\
             [dependencies]\nws-core = {{ version = \"=0.1.0\", path = \"../ws-core\" }}\n"
        ),
        Some("pub fn doubled() -> u32 { ws_core::value() * 2 }\n"),
        None,
    );
    write_tier1_license(&root.join("crates/ws-mid"));

    write_crate(
        root,
        "crates/ws-app",
        &format!(
            "[package]\nname = \"ws-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER2_LICENSE_SPDX}\"\n\n\
             [dependencies]\nws-mid = {{ version = \"=0.1.0\", path = \"../ws-mid\" }}\n"
        ),
        Some("pub fn run() -> u32 { ws_mid::doubled() }\n"),
        Some("fn main() { println!(\"{}\", ws_app::run()); }\n"),
    );
    write_tier2_license(&root.join("crates/ws-app"));

    let metadata = load_cargo_metadata(&root.join("Cargo.toml")).expect("load real cargo metadata");
    let plan = compute_publish_plan(&metadata, &[]).expect("compute topological plan");
    let names: Vec<&str> = plan
        .ordered_packages
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, vec!["ws-core", "ws-mid", "ws-app"]);

    let tiers = verify_workspace_licenses(&plan, LicensePolicyMode::Auto)
        .expect("verify two-tier licensing");
    assert_eq!(tiers["ws-core"], LicenseTier::Tier1LgplLinkingException);
    assert_eq!(tiers["ws-mid"], LicenseTier::Tier1LgplLinkingException);
    assert_eq!(tiers["ws-app"], LicenseTier::Tier2Agpl3);
}

#[test]
fn test_real_cargo_metadata_rejects_missing_dep_version_and_license_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/ws-core\", \"crates/ws-mid\"]\nresolver = \"2\"\n",
    )
    .expect("write Cargo.toml");

    write_crate(
        root,
        "crates/ws-core",
        &format!(
            "[package]\nname = \"ws-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER1_LICENSE_SPDX}\"\n"
        ),
        Some("pub fn ok() -> bool { true }\n"),
        None,
    );
    // Intentionally write plain LGPL without linking exception.
    fs::write(
        root.join("crates/ws-core/LICENSE"),
        "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n",
    )
    .expect("write LICENSE");

    // ws-mid omits `version = ...` on its path dependency -> cargo metadata emits `req = "*"`.
    write_crate(
        root,
        "crates/ws-mid",
        &format!(
            "[package]\nname = \"ws-mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER1_LICENSE_SPDX}\"\n\n\
             [dependencies]\nws-core = {{ path = \"../ws-core\" }}\n"
        ),
        Some("pub fn check() -> bool { ws_core::ok() }\n"),
        None,
    );
    write_tier1_license(&root.join("crates/ws-mid"));

    let metadata = load_cargo_metadata(&root.join("Cargo.toml")).expect("load cargo metadata");
    let err = compute_publish_plan(&metadata, &[]).expect_err("missing dep version must fail");
    assert!(matches!(
        err,
        DeployError::MissingVersion {
            ref package,
            dependency: Some(ref dep),
            ..
        } if package == "ws-mid" && dep == "ws-core"
    ));

    // Add explicit version on ws-mid, then verify license gate catches missing linking exception on ws-core.
    fs::write(
        root.join("crates/ws-mid/Cargo.toml"),
        format!(
            "[package]\nname = \"ws-mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"{TIER1_LICENSE_SPDX}\"\n\n\
             [dependencies]\nws-core = {{ version = \"=0.1.0\", path = \"../ws-core\" }}\n"
        ),
    )
    .expect("update Cargo.toml");

    let metadata2 = load_cargo_metadata(&root.join("Cargo.toml")).expect("reload cargo metadata");
    let plan = compute_publish_plan(&metadata2, &[]).expect("plan succeeds");
    let lic_err = verify_workspace_licenses(&plan, LicensePolicyMode::Auto)
        .expect_err("missing linking exception must fail");
    assert!(matches!(
        lic_err,
        DeployError::LicensePolicyViolation { ref package, .. } if package == "ws-core"
    ));
}

#[test]
fn test_end_to_end_muregist_staging_publish_etag_poll_and_clean_room_consumer_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    let server = MockMuRegistServer::start("test-muregist-token");
    std::env::set_var("MU_TEST_MUREGIST_TOKEN", "test-muregist-token");

    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/ws-core\", \"crates/ws-mid\"]\nresolver = \"2\"\n",
    )
    .expect("write workspace Cargo.toml");

    write_crate(
        root,
        "crates/ws-core",
        &format!(
            "[package]\nname = \"ws-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             license = \"{TIER1_LICENSE_SPDX}\"\n\
             description = \"Tier 1 foundation library\"\n"
        ),
        Some("pub fn greeting() -> &'static str { \"muregist-ok\" }\n"),
        None,
    );
    write_tier1_license(&root.join("crates/ws-core"));

    write_crate(
        root,
        "crates/ws-mid",
        &format!(
            "[package]\nname = \"ws-mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             license = \"{TIER1_LICENSE_SPDX}\"\n\
             description = \"Tier 1 dependent library\"\n\n\
             [dependencies]\n\
             ws-core = {{ version = \"=0.1.0\", path = \"../ws-core\", registry = \"muregist\" }}\n"
        ),
        Some("pub fn message() -> &'static str { ws_core::greeting() }\n"),
        None,
    );
    write_tier1_license(&root.join("crates/ws-mid"));

    // Also configure a workspace `.cargo/config.toml` that blocks crates.io egress inside the test project.
    fs::create_dir_all(root.join(".cargo")).expect("mkdir .cargo");
    fs::create_dir_all(root.join("forbidden-crates-io-vendor")).expect("mkdir empty vendor");
    fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[registries.muregist]\nindex = \"sparse+{}/index/\"\n\n\
             [source.crates-io]\nreplace-with = \"forbidden-crates-io\"\n\n\
             [source.forbidden-crates-io]\ndirectory = \"forbidden-crates-io-vendor\"\n",
            server.base_url()
        ),
    )
    .expect("write workspace .cargo/config.toml");

    let inv = ToolInvocation::new("cargo-deploy", ["--allow-dirty", "--no-verify"])
        .with_param("registry", "muregist")
        .with_param("registry_url", server.base_url())
        .with_param("token_env", "MU_TEST_MUREGIST_TOKEN")
        .with_param("poll_timeout_secs", 10_i64);

    let params = CargoDeployParams::from_invocation(&inv).expect("valid invocation params");
    let mut exec_cfg = CargoDeployExecutionConfig::new(root.join("Cargo.toml"), params);
    exec_cfg.run_id = Some("e2e-muregist-stage-1".to_string());
    exec_cfg.poll_interval = Duration::from_millis(25);

    let report = execute_cargo_deploy(&exec_cfg, &SystemCargoRunner, &HttpSparseIndexClient)
        .expect("end-to-end staging must succeed");

    assert_eq!(report.run_id, "e2e-muregist-stage-1");
    assert_eq!(report.ecosystem, "cargo");
    assert_eq!(report.registry, "muregist");
    assert_eq!(report.status, "passed");
    assert!(!report.dry_run);
    assert_eq!(report.publish_order.len(), 2);
    assert_eq!(report.publish_order[0].name, "ws-core");
    assert!(report.publish_order[0].published);
    assert!(report.publish_order[0]
        .etag
        .as_deref()
        .is_some_and(|tag| tag.starts_with("\"sha256:")));
    assert_eq!(report.publish_order[1].name, "ws-mid");
    assert!(report.publish_order[1].published);
    assert!(report.publish_order[1]
        .etag
        .as_deref()
        .is_some_and(|tag| tag.starts_with("\"sha256:")));
    assert!(report.consumer_check.executed);
    assert!(report.consumer_check.passed);
    assert!(report.consumer_check.isolated_cargo_home);
    assert!(report.consumer_check.crates_io_blocked);
    assert_eq!(
        report.consumer_check.checked_packages,
        vec!["ws-core".to_string(), "ws-mid".to_string()]
    );

    let state = server.state.lock().expect("lock server state");
    assert_eq!(
        state.publish_sequence,
        vec!["ws-core@0.1.0".to_string(), "ws-mid@0.1.0".to_string()]
    );
    assert!(state
        .requests
        .iter()
        .any(|r| r == "GET /api/v1/crates/ws-core/0.1.0/download"));
    assert!(state
        .requests
        .iter()
        .any(|r| r == "GET /api/v1/crates/ws-mid/0.1.0/download"));

    let stdout_json = serde_json::to_string(&report).expect("serialize report");
    let metrics = CargoDeployAdapter
        .parse_metrics(stdout_json.as_bytes(), b"", 0)
        .expect("parse metrics");
    assert_eq!(metrics.cd_staging_report, Some(report));
}

#[test]
fn test_sparse_index_etag_conditional_and_clean_room_blocks_crates_io() {
    use mu_ci_tools::adapters::deploy::{
        poll_sparse_index_etag, ConsumerCheckRequest, SparseIndexClient,
    };
    use mu_ci_tools::CargoRunner;

    let server = MockMuRegistServer::start("token-1");
    let rel_missing = cargo_index_relative_path("missing-crate").expect("valid path");

    // Missing crate must time out with bounded IndexPollTimeout.
    let timeout_err = poll_sparse_index_etag(
        &HttpSparseIndexClient,
        &server.base_url(),
        "missing-crate",
        "0.1.0",
        Duration::from_millis(80),
        Duration::from_millis(20),
    )
    .expect_err("missing index entry should time out");
    assert!(matches!(
        timeout_err,
        DeployError::IndexPollTimeout { ref index_path, .. } if index_path == &rel_missing
    ));

    // Seed an index entry directly in mock server and verify ETag + If-None-Match 304 behavior.
    {
        let mut guard = server.state.lock().expect("lock");
        let seeded_rel = cargo_index_relative_path("seeded-lib").unwrap();
        let entry = "{\"name\":\"seeded-lib\",\"vers\":\"0.1.0\",\"deps\":[],\"cksum\":\"00\",\"features\":{},\"yanked\":false}\n";
        guard
            .index_lines
            .insert(seeded_rel.clone(), vec![entry.trim().to_string()]);
        guard
            .index_etags
            .insert(seeded_rel.clone(), "\"sha256:seeded123\"".to_string());
    }

    let (polled_rel, etag) = poll_sparse_index_etag(
        &HttpSparseIndexClient,
        &server.base_url(),
        "seeded-lib",
        "0.1.0",
        Duration::from_secs(1),
        Duration::from_millis(20),
    )
    .expect("poll returns seeded ETag");
    assert_eq!(etag, "\"sha256:seeded123\"");

    let cond_resp = HttpSparseIndexClient
        .fetch_index_entry(&server.base_url(), &polled_rel, Some(&etag))
        .expect("conditional fetch succeeds");
    assert_eq!(cond_resp.status_code, 304);

    // Requesting a crate absent from muregist (would require crates.io) must fail closed in clean-room check.
    let err = SystemCargoRunner
        .run_clean_room_consumer_check(&ConsumerCheckRequest {
            library_packages: vec![(
                "nonexistent-upstream-crate".to_string(),
                "1.0.0".to_string(),
            )],
            registry_url: server.base_url(),
            locked: false,
        })
        .expect_err("clean-room consumer check must fail without crates.io egress");
    assert!(matches!(err, DeployError::ConsumerCheckFailed { .. }));
}
