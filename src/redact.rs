//! 凭据打码（DESIGN.md §5.3）。
//!
//! **这是设计决策不是实现细节**：一个用于安全调查的工具，如果默认把密钥写进日志，
//! 它本身就是新的泄漏面。实测证据（§5.3）：验证 argv 读取时输出里直接出现了
//! `redis-cli -a myredissecret`。
//!
//! 默认 `--redact argv`；`argv+content` 额外打码 agent 层 preview。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// 不打码（明确警告用户）。
    Off,
    /// 打码 argv 与 Bash 命令（**默认**）。
    Argv,
    /// 额外打码 agent 层 preview（prompt/thinking/tool 结果）。
    ArgvContent,
}

impl RedactMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(RedactMode::Off),
            "argv" => Ok(RedactMode::Argv),
            "argv+content" => Ok(RedactMode::ArgvContent),
            other => Err(format!(
                "unknown --redact value `{}` (available: off | argv | argv+content)",
                other
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RedactMode::Off => "off",
            RedactMode::Argv => "argv",
            RedactMode::ArgvContent => "argv+content",
        }
    }

    pub fn redacts_argv(self) -> bool {
        !matches!(self, RedactMode::Off)
    }

    pub fn redacts_content(self) -> bool {
        matches!(self, RedactMode::ArgvContent)
    }
}

pub const MASK: &str = "***";

/// 需要吃掉"下一个参数"的敏感 flag（长短形式）。
const SENSITIVE_FLAGS: &[&str] = &[
    "-a",
    "--password",
    "--passwd",
    "--token",
    "--api-key",
    "--apikey",
    "--api_key",
    "--secret",
    "--client-secret",
    "--auth",
    "--bearer",
    "--access-token",
    "--refresh-token",
    "--private-key",
    "--passphrase",
    "--password-file",
];
// 注意：**故意不含** `-p`（curl/nc 里是 port）和 `-w`（curl 的 write-out format）。
// 宁可漏打一个短选项，也不要把 `curl -w '%{http_code}'` 这种常见命令打码成噪声。

/// `key=value` 形态里敏感的 key（小写比较）。
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "bearer",
    "private_key",
    "passphrase",
    "credential",
    "credentials",
];

/// 需要打码其值的 header 名（大小写不敏感）。
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "x-amz-security-token",
];

/// 纯十六进制且长度是典型摘要长度 → 更可能是哈希/提交号，不是密钥。
///
/// 这个例外是**故意的**：`git checkout 3f2a…（40 位）` 是日常操作，
/// 把它打码成 `***` 会让人没法用这个工具。宁可放过一个恰好是纯 hex 的密钥
/// （极罕见，密钥通常含大小写混合或 base64 字符），也不要天天误伤提交号。
fn looks_like_hex_digest(s: &str) -> bool {
    let n = s.len();
    if !matches!(n, 32 | 40 | 64 | 128) {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 一个 argv 参数是否需要整体打码（形如长随机串）。
///
/// 阈值取 20：AWS access key id 恰好是 20 字符（`AKIA` + 16），
/// 这是最常见的"一眼就是密钥"的形态，卡在 24 会漏掉它。
fn looks_like_secret_token(s: &str) -> bool {
    let n = s.chars().count();
    if n < 20 {
        return false;
    }
    if looks_like_hex_digest(s) {
        return false;
    }
    // 明显的路径 / URL / 选项不当作 token。
    if s.starts_with('-') || s.contains("://") || s.starts_with('/') || s.starts_with('.') {
        return false;
    }
    let body = s.trim_end_matches('=');
    if body.is_empty() {
        return false;
    }
    if !body
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-' | '=' | '.'))
    {
        return false;
    }
    // 纯字母或纯数字的长串更可能是普通标识符/哈希之外的东西；要求至少有两类字符。
    let has_lower = body.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = body.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = body.chars().any(|c| c.is_ascii_digit());
    let classes = [has_lower, has_upper, has_digit].iter().filter(|b| **b).count();
    // 含 '.' 的通常是文件名/域名 → 要求三类字符齐全才算 token。
    if body.contains('.') && classes < 3 {
        return false;
    }
    classes >= 2
}

/// 打码一个 `Header: value` 形态的串。返回 Some(打码后的串) 表示命中了。
fn redact_header_line(s: &str) -> Option<String> {
    let colon = s.find(':')?;
    let (name, _) = s.split_at(colon);
    let name_l = name.trim().to_ascii_lowercase();
    if SENSITIVE_HEADERS.contains(&name_l.as_str()) {
        return Some(format!("{}: {}", name.trim(), MASK));
    }
    None
}

/// 打码 `Bearer <token>` / `Basic <token>` 形态（出现在任意位置）。
fn redact_auth_scheme(s: &str) -> Option<String> {
    for scheme in ["Bearer", "bearer", "Basic", "basic", "token"] {
        if let Some(pos) = s.find(scheme) {
            let after = &s[pos + scheme.len()..];
            let ws = after.len() - after.trim_start().len();
            if ws == 0 {
                continue;
            }
            let rest = after.trim_start();
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            if end == 0 {
                continue;
            }
            let mut out = String::with_capacity(s.len());
            out.push_str(&s[..pos]);
            out.push_str(scheme);
            out.push_str(&after[..ws]);
            out.push_str(MASK);
            out.push_str(&rest[end..]);
            return Some(out);
        }
    }
    None
}

/// 打码 `key=value` 形态里敏感的 key。
fn redact_kv(s: &str) -> Option<String> {
    let eq = s.find('=')?;
    let (k, _) = s.split_at(eq);
    let key_part = k
        .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .next()?;
    if SENSITIVE_KEYS.contains(&key_part.to_ascii_lowercase().as_str()) {
        return Some(format!("{}={}", k, MASK));
    }
    None
}

/// 对任意文本做凭据打码（用于 Bash 命令串、tool input、preview）。
pub fn redact_text(s: &str) -> String {
    let mut cur = s.to_string();
    // header 形态优先（`Authorization: Bearer xxx` 要被整段吃掉）
    if let Some(v) = redact_header_line(&cur) {
        return v;
    }
    // 反复应用 auth scheme / kv，直到稳定（一条命令里可能有多个凭据）。
    for _ in 0..8 {
        let mut changed = false;
        if let Some(v) = redact_auth_scheme(&cur) {
            if v != cur {
                cur = v;
                changed = true;
            }
        }
        if let Some(v) = redact_kv(&cur) {
            if v != cur {
                cur = v;
                changed = true;
            }
        }
        // flag + value 形态（`-a secret` / `--token=secret`）
        if let Some(v) = redact_flag_value(&cur) {
            if v != cur {
                cur = v;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    cur
}

/// 在**整串**里按空白切词，打码 `-a secret` 这类相邻形态。
fn redact_flag_value(s: &str) -> Option<String> {
    let toks: Vec<&str> = s.split(' ').collect();
    if toks.len() < 2 && !s.contains('=') {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(toks.len());
    let mut i = 0;
    let mut hit = false;
    while i < toks.len() {
        let t = toks[i];
        // `--flag=value`
        if let Some(eq) = t.find('=') {
            let (name, _) = t.split_at(eq);
            if SENSITIVE_FLAGS.contains(&name) {
                out.push(format!("{}={}", name, MASK));
                hit = true;
                i += 1;
                continue;
            }
        }
        if SENSITIVE_FLAGS.contains(&t) && i + 1 < toks.len() {
            out.push(t.to_string());
            out.push(MASK.to_string());
            hit = true;
            i += 2;
            continue;
        }
        out.push(t.to_string());
        i += 1;
    }
    if hit { Some(out.join(" ")) } else { None }
}

/// 打码 argv 列表。返回 (打码后的 argv, 是否有任何改动)。
pub fn redact_argv(argv: &[String]) -> (Vec<String>, bool) {
    let mut out = Vec::with_capacity(argv.len());
    let mut changed = false;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        // 1) 敏感 flag 吃掉下一个参数
        if SENSITIVE_FLAGS.contains(&a.as_str()) && i + 1 < argv.len() {
            out.push(a.clone());
            out.push(MASK.to_string());
            changed = true;
            i += 2;
            continue;
        }
        // 2) `--flag=value`
        if let Some(eq) = a.find('=') {
            let (name, _) = a.split_at(eq);
            if SENSITIVE_FLAGS.contains(&name) {
                out.push(format!("{}={}", name, MASK));
                changed = true;
                i += 1;
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if SENSITIVE_KEYS.contains(&lower.trim_start_matches('-')) {
                out.push(format!("{}={}", name, MASK));
                changed = true;
                i += 1;
                continue;
            }
        }
        // 3) header / auth scheme / kv 形态
        let t = redact_text(a);
        if t != *a {
            changed = true;
            out.push(t);
            i += 1;
            continue;
        }
        // 4) 整串看起来就是密钥
        if looks_like_secret_token(a) {
            out.push(MASK.to_string());
            changed = true;
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    (out, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// 验收 §7 #6：`redis-cli -a <secret>` 形式的密钥必须被打码。
    #[test]
    fn redis_cli_password_masked() {
        let (out, changed) = redact_argv(&argv(&["redis-cli", "-a", "myredissecret"]));
        assert!(changed);
        assert_eq!(out, argv(&["redis-cli", "-a", "***"]));
        assert!(!out.iter().any(|a| a.contains("myredissecret")));
    }

    /// 验收 §7 #5 的形态：`curl -H "Authorization: Bearer xxx"`。
    #[test]
    fn curl_authorization_header_masked() {
        let (out, changed) = redact_argv(&argv(&[
            "curl",
            "-H",
            "Authorization: Bearer sk-live-abcdef0123456789",
            "https://example.com",
        ]));
        assert!(changed, "Authorization header 未被识别: {:?}", out);
        assert!(!out.iter().any(|a| a.contains("sk-live")), "{:?}", out);
        // 非敏感参数必须原样保留
        assert!(out.contains(&"https://example.com".to_string()));
    }

    #[test]
    fn long_flag_and_eq_forms() {
        let (o1, _) = redact_argv(&argv(&["tool", "--token", "abc123"]));
        assert_eq!(o1[2], "***");
        let (o2, _) = redact_argv(&argv(&["tool", "--token=abc123"]));
        assert_eq!(o2[1], "--token=***");
        let (o3, _) = redact_argv(&argv(&["tool", "password=hunter2"]));
        assert_eq!(o3[1], "password=***");
    }

    #[test]
    fn high_entropy_token_masked() {
        let (o, changed) = redact_argv(&argv(&["tool", "AKIA9fJ2kLm3Np4Qr7St"]));
        assert!(changed && o[1] == "***", "{:?}", o);
    }

    /// **不能误伤**常见良性参数 —— 这是打码器最容易出错的地方。
    #[test]
    fn benign_args_untouched() {
        for a in [
            "curl",
            "-s",
            "-m",
            "2",
            "http://127.0.0.1:6379/",
            "/home/viktor/agtrace",
            "/tmp/x.txt",
            "--no-verbose",
            "PATH=/usr/bin:/bin",
            "sleep",
            "2",
            "postgres",
            "SELECT * FROM t",
            "hello-agtrace",
            "-U",
            "--tries=1",
            // 真实会出现在命令行里的东西：
            "3f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c", // git 提交号（40 位 hex）
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // sha256
            "--depth=1",
            "refs/heads/main",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80912", // 40 位 hex
        ] {
            let (o, changed) = redact_argv(&argv(&[a]));
            assert!(!changed, "良性参数被误伤: {} -> {:?}", a, o);
        }
    }

    /// 20 字符的 AWS access key id 必须被打码（阈值定在 20 的原因）。
    #[test]
    fn aws_key_id_masked() {
        let (o, changed) = redact_argv(&argv(&["aws", "s3", "ls", "AKIAIOSFODNN7EXAMPLE"]));
        assert!(changed, "{:?}", o);
        assert!(o.iter().any(|a| a == MASK), "{:?}", o);
    }

    #[test]
    fn bash_command_text_masked() {
        let s = "curl -H 'Authorization: Bearer tok123456' https://x.dev";
        let r = redact_text(s);
        assert!(!r.contains("tok123456"), "{}", r);
    }

    #[test]
    fn word_boundary_not_broken() {
        // `-w` 是 curl 的 write-out，但也在敏感 flag 列表里（--password-file 的短形式是 -w 吗？）
        // 这里只断言不 panic 且长度合理；具体取舍见 BUILD_LOG。
        let (o, _) = redact_argv(&argv(&["curl", "-w", "%{http_code}"]));
        assert_eq!(o.len(), 3);
    }
}
