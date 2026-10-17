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
///
/// 匹配发生在**整串的任意位置**（不只是行首）：命令里常见
/// `bash -c "curl -H 'Cookie: ...'"`、`curl -H 'X-Api-Key: ...'` 这种形态。
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "private-token",
    "x-amz-security-token",
];

/// JSON / JSON-in-a-command 里敏感的 key（小写比较）。是 [`SENSITIVE_KEYS`]
/// 与 [`SENSITIVE_HEADERS`] 的并集：`curl -d '{"password":"..."}'` 和
/// `{"X-Api-Key": "..."}` 都要打码。
const SENSITIVE_JSON_KEYS: &[&str] = &[
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
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "private-token",
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

// ---------------------------------------------------------------------------
// Span-based masking helpers (F4)
//
// Every pattern masks **only the credential value/token span** and leaves the
// rest of the input byte-for-byte intact. The previous implementation returned
// a rebuilt prefix (`format!("{}={}", k, MASK)`), which silently deleted
// everything after the secret — `echo 'PASSWORD=x' && rm -rf /` lost the
// `&& rm -rf /`. A debugger that edits the evidence is not a debugger.
// ---------------------------------------------------------------------------

/// Replace `s[start..end]` with [`MASK`], keeping everything else unchanged.
/// Callers pass char-boundary byte indices (never mid-codepoint).
fn mask_span(s: &str, start: usize, end: usize) -> String {
    let mut out = String::with_capacity(s.len() - (end - start) + MASK.len());
    out.push_str(&s[..start]);
    out.push_str(MASK);
    out.push_str(&s[end..]);
    out
}

/// Characters allowed in a header/key token: alnum, `_`, `-`.
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Skip spaces/tabs (not newlines: a header value ends at the line break).
fn skip_hspace(s: &str, mut i: usize) -> usize {
    while i < s.len() {
        match s[i..].chars().next() {
            Some(' ') | Some('\t') => i += 1,
            _ => break,
        }
    }
    i
}

/// End of a bare value token: whitespace or punctuation belonging to the
/// surrounding syntax (`'`, `"`, `,`, `}`, `&&`, `;`, ...). Punctuation is
/// never consumed — it belongs to the remainder, not to the secret.
fn value_end(s: &str, start: usize) -> usize {
    let mut end = s.len();
    for (i, c) in s[start..].char_indices() {
        if c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '}' | ')' | ']' | '&' | ';' | '|' | '`') {
            end = start + i;
            break;
        }
    }
    end
}

/// Mask URL userinfo passwords: `https://user:token@host` → `https://user:***@host`.
///
/// The host is intentionally kept: it is the part that is useful for debugging,
/// while the userinfo password is the credential. Userinfo without a colon
/// (`https://user@host`) is left alone — it is far more often a username than a
/// secret (masking ordinary URLs would be a false positive).
fn redact_url_userinfo(s: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = s[from..].find("://") {
        let scheme_end = from + rel;
        let authority_start = scheme_end + 3;
        let mut authority_end = s.len();
        let mut at = None;
        for (i, c) in s[authority_start..].char_indices() {
            let abs = authority_start + i;
            if c == '@' {
                at = Some(abs);
            }
            if c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '&' | ';' | ',' | ')' | ']') {
                authority_end = abs;
                break;
            }
        }
        if let Some(at) = at
            && at < authority_end
            && let Some(rel_colon) = s[authority_start..at].find(':')
        {
            let vs = authority_start + rel_colon + 1;
            if at > vs && &s[vs..at] != MASK {
                return Some(mask_span(s, vs, at));
            }
        }
        from = scheme_end + 3;
    }
    None
}

/// Mask the value of a sensitive header appearing **anywhere** in the string,
/// e.g. `curl -H 'Cookie: sid=...'` or a bare `X-Api-Key: ...`.
///
/// The value ends at end-of-string, a line break, or the quote that closes the
/// enclosing shell string — so the remainder of the command (`&& rm -rf /`,
/// the URL after the closing quote) is preserved verbatim (F4).
fn redact_header_line(s: &str) -> Option<String> {
    for (colon, c) in s.char_indices() {
        if c != ':' {
            continue;
        }
        // Header name immediately before the colon.
        let mut name_start = colon;
        for (i, ch) in s[..colon].char_indices().rev() {
            if is_key_char(ch) {
                name_start = i;
            } else {
                break;
            }
        }
        if name_start == colon {
            continue;
        }
        let name = s[name_start..colon].to_ascii_lowercase();
        if !SENSITIVE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let vs = skip_hspace(s, colon + 1);
        let mut ve = vs;
        for (i, ch) in s[vs..].char_indices() {
            if ch == '\n' || ch == '\r' || ch == '"' || ch == '\'' {
                break;
            }
            ve = vs + i + ch.len_utf8();
        }
        if ve > vs && &s[vs..ve] != MASK {
            return Some(mask_span(s, vs, ve));
        }
    }
    None
}

/// Mask `Bearer <token>` / `Basic <token>` / `token <token>` anywhere in the
/// string. Only the token span is replaced; already-masked occurrences are
/// skipped so several credentials in one line are all masked.
fn redact_auth_scheme(s: &str) -> Option<String> {
    let mut from = 0;
    while from < s.len() {
        let mut best: Option<(usize, &str)> = None;
        for scheme in ["Bearer", "bearer", "Basic", "basic", "token"] {
            if let Some(rel) = s[from..].find(scheme) {
                let pos = from + rel;
                if best.map(|(b, _)| pos < b).unwrap_or(true) {
                    best = Some((pos, scheme));
                }
            }
        }
        let Some((pos, scheme)) = best else {
            break;
        };
        let after = &s[pos + scheme.len()..];
        let ws = after.len() - after.trim_start().len();
        let mut next = pos + scheme.len();
        if ws > 0 {
            let rest = after.trim_start();
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            if end > 0 {
                let vs = pos + scheme.len() + ws;
                let ve = vs + end;
                if &s[vs..ve] != MASK {
                    return Some(mask_span(s, vs, ve));
                }
                next = ve;
            }
        }
        from = next;
    }
    None
}

/// Mask `"password": "..."` / `"token":"..."` values inside a JSON body that
/// appears in a command (`curl -d '{"password":"hunter2"}'`). Only the quoted
/// value is replaced; the JSON structure and the rest of the command survive.
fn redact_json_kv(s: &str) -> Option<String> {
    let quotes: Vec<usize> = s.char_indices().filter(|(_, c)| *c == '"').map(|(i, _)| i).collect();
    let mut qi = 0;
    while qi + 1 < quotes.len() {
        let k_open = quotes[qi];
        let k_close = quotes[qi + 1];
        let key = s[k_open + 1..k_close].to_ascii_lowercase();
        let mut j = skip_hspace(s, k_close + 1);
        let is_pair = j < s.len() && s[j..].starts_with(':') && SENSITIVE_JSON_KEYS.contains(&key.as_str());
        if !is_pair {
            qi += 1;
            continue;
        }
        j = skip_hspace(s, j + 1);
        if j >= s.len() || !s[j..].starts_with('"') {
            qi += 1;
            continue;
        }
        let v_open = j;
        let mut v_close = None;
        let mut k = v_open + 1;
        while k < s.len() {
            let ch = s[k..].chars().next().unwrap();
            if ch == '\\' {
                k += 1;
                if k < s.len() {
                    k += s[k..].chars().next().unwrap().len_utf8();
                }
                continue;
            }
            if ch == '"' {
                v_close = Some(k);
                break;
            }
            k += ch.len_utf8();
        }
        let Some(v_close) = v_close else {
            qi += 1;
            continue;
        };
        if v_close > v_open + 1 && &s[v_open + 1..v_close] != MASK {
            return Some(mask_span(s, v_open + 1, v_close));
        }
        qi = quotes.partition_point(|q| *q <= v_close);
    }
    None
}

/// Mask a `key=value` pair whose key is sensitive (`PASSWORD=x`,
/// `--token=abc`, `api_key=...`). Only the value span is replaced, so
/// `echo 'PASSWORD=x' && rm -rf /` keeps the `&& rm -rf /` (F4).
fn redact_kv(s: &str) -> Option<String> {
    for (eq, c) in s.char_indices() {
        if c != '=' {
            continue;
        }
        let mut key_start = eq;
        for (i, ch) in s[..eq].char_indices().rev() {
            if is_key_char(ch) {
                key_start = i;
            } else {
                break;
            }
        }
        if key_start == eq {
            continue;
        }
        let key = s[key_start..eq].trim_start_matches('-').to_ascii_lowercase();
        if !SENSITIVE_KEYS.contains(&key.as_str()) {
            continue;
        }
        let after = eq + 1;
        if after >= s.len() {
            continue;
        }
        let (vs, ve) = {
            let quote = s[after..].chars().next().unwrap();
            if quote == '"' || quote == '\'' {
                let mut close = None;
                for (i, ch) in s[after + 1..].char_indices() {
                    if ch == quote {
                        close = Some(after + 1 + i);
                        break;
                    }
                }
                (after + 1, close.unwrap_or(s.len()))
            } else {
                (after, value_end(s, after))
            }
        };
        if ve > vs && &s[vs..ve] != MASK {
            return Some(mask_span(s, vs, ve));
        }
    }
    None
}

/// 对任意文本做凭据打码（用于 Bash 命令串、tool input、preview）。
///
/// 每个 pass 只替换**命中的那一个值**，其余字节原样保留（F4）；循环到不再
/// 命中为止，所以一行里的多个凭据（header + URL userinfo + JSON body）都会
/// 被吃掉。
pub fn redact_text(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..64 {
        let next = redact_url_userinfo(&cur)
            .or_else(|| redact_header_line(&cur))
            .or_else(|| redact_auth_scheme(&cur))
            .or_else(|| redact_json_kv(&cur))
            .or_else(|| redact_kv(&cur))
            .or_else(|| redact_flag_value(&cur));
        match next {
            Some(v) => cur = v,
            None => break,
        }
    }
    cur
}

/// 在**整串**里按空白切词，打码 `-a secret` / `--token=abc` 这类相邻形态。
///
/// 只替换值的 span，值后面的标点（引号、逗号、`&&`、JSON 的 `}`）保留 ——
/// 命令串里嵌着 JSON 时（`-d '{"password":"..."}'`）不能把结构吃掉。
fn redact_flag_value(s: &str) -> Option<String> {
    let mut i = 0;
    while i < s.len() {
        // token 起点
        while i < s.len() && s[i..].chars().next().is_some_and(char::is_whitespace) {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let t_start = i;
        let mut t_end = s.len();
        for (j, c) in s[i..].char_indices() {
            if c.is_whitespace() {
                t_end = i + j;
                break;
            }
        }
        let token = &s[t_start..t_end];
        if let Some(eq) = token.find('=') {
            let (name, _) = token.split_at(eq);
            if SENSITIVE_FLAGS.contains(&name) {
                let vs = t_start + eq + 1;
                let ve = value_end(s, vs);
                if ve > vs && &s[vs..ve] != MASK {
                    return Some(mask_span(s, vs, ve));
                }
            }
        } else if SENSITIVE_FLAGS.contains(&token) {
            let mut j = t_end;
            while j < s.len() && s[j..].chars().next().is_some_and(char::is_whitespace) {
                j += 1;
            }
            if j < s.len() {
                let ve = value_end(s, j);
                if ve > j && &s[j..ve] != MASK {
                    return Some(mask_span(s, j, ve));
                }
            }
        }
        i = if t_end > t_start { t_end } else { t_start + 1 };
    }
    None
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

    // ===========================================================
    // F3：默认 argv 模式漏掉的三种形态（URL userinfo / 任意位置 header /
    // JSON body），以及 F4：只替换凭据值、其余字节必须原样保留。
    // ===========================================================

    /// F3(a)：URL userinfo 里的密码必须打码，host 保留（host 是排障有用的那半）。
    #[test]
    fn url_userinfo_password_masked() {
        let r = redact_text("curl https://user:tok3n@example.com/v1");
        assert_eq!(r, "curl https://user:***@example.com/v1");
        assert!(!r.contains("tok3n"));
        // 没有 userinfo 的 URL 不得被误伤
        assert_eq!(
            redact_text("https://example.com/path?q=1"),
            "https://example.com/path?q=1"
        );
    }

    /// URL userinfo 与 `key=value` 可以同时出现在一行里。
    #[test]
    fn url_userinfo_masked_inside_assignment() {
        let r = redact_text("DATABASE_URL=postgres://user:pw123@localhost:5432/db");
        assert_eq!(r, "DATABASE_URL=postgres://user:***@localhost:5432/db");
        assert!(!r.contains("pw123"));
    }

    /// F3(b)：header 不在字符串开头时也必须命中
    /// （`bash -c "curl -H 'Cookie: ...'"` 是真实会出现的形态）。
    #[test]
    fn header_not_at_string_start_masked() {
        let r = redact_text("bash -c \"curl -H 'Cookie: sid=abc123' https://x\"");
        assert_eq!(r, "bash -c \"curl -H 'Cookie: ***' https://x\"");
        assert!(!r.contains("sid=abc123"));
    }

    /// F3(b)：大小写不敏感，且任意 header 名（含 `X-Api-Key`/`private-token`）。
    #[test]
    fn api_key_headers_masked_case_insensitively() {
        assert_eq!(
            redact_text("curl -H 'X-Api-Key: sk-live-abc' https://x"),
            "curl -H 'X-Api-Key: ***' https://x"
        );
        assert_eq!(redact_text("x-api-key: sk-live-abc"), "x-api-key: ***");
        assert_eq!(redact_text("PRIVATE-TOKEN: glpat-xyz"), "PRIVATE-TOKEN: ***");
        assert_eq!(redact_text("Cookie: a=b; HttpOnly"), "Cookie: ***");
    }

    /// F3(c)：JSON body 里的 password / token 值必须打码，JSON 结构保留。
    #[test]
    fn json_body_password_masked() {
        let r = redact_text(r#"curl -d '{"password":"hunter2"}' https://x"#);
        assert_eq!(r, r#"curl -d '{"password":"***"}' https://x"#);
        assert!(!r.contains("hunter2"));
    }

    #[test]
    fn json_body_token_masked() {
        let r = redact_text(r#"{"token": "eyJhbGciOiJIUzI1NiJ9"}"#);
        assert_eq!(r, r#"{"token": "***"}"#);
        assert!(!r.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    /// F4 回归：header 打码后**整条命令的剩余部分原样保留**，不得被截掉。
    #[test]
    fn header_mask_keeps_the_rest_of_the_command() {
        let r = redact_text("curl -H 'Authorization: Bearer topsecret' && rm -rf /");
        assert_eq!(r, "curl -H 'Authorization: ***' && rm -rf /");
        assert!(r.ends_with("&& rm -rf /"), "余下命令被吃掉: {}", r);
    }

    /// F4 回归（reviewer 指定的用例）：`echo 'PASSWORD=x' && rm -rf /`
    /// 之前会退化成 `echo 'PASSWORD=***`，把 `' && rm -rf /` 整段删掉。
    #[test]
    fn kv_mask_keeps_the_rest_of_the_command() {
        let r = redact_text("echo 'PASSWORD=x' && rm -rf /");
        assert_eq!(r, "echo 'PASSWORD=***' && rm -rf /");
        assert!(r.contains("&& rm -rf /"), "余下命令被吃掉: {}", r);
    }

    /// 一条命令里多个凭据必须全部打码（header + header）。
    #[test]
    fn multiple_credentials_in_one_line_all_masked() {
        let r = redact_text("curl -H 'Cookie: sid=1' -H 'X-Api-Key: sk-2'");
        assert_eq!(r, "curl -H 'Cookie: ***' -H 'X-Api-Key: ***'");
        assert!(!r.contains("sid=1") && !r.contains("sk-2"), "{}", r);
    }

    /// F1 依赖的行为：命令串里嵌的 JSON 被 `-a secret` 打码时不能吃掉结构。
    #[test]
    fn flag_mask_inside_json_keeps_structure() {
        let r = redact_text(r#"{"command":"redis-cli -a s3cr3t"}"#);
        assert_eq!(r, r#"{"command":"redis-cli -a ***"}"#);
    }

    /// argv 元素里的 URL userinfo 也要打码（内核 argv 路径走的是 redact_argv）。
    #[test]
    fn argv_url_userinfo_masked() {
        let (o, changed) = redact_argv(&argv(&["curl", "https://user:tok@host/x"]));
        assert!(changed, "{:?}", o);
        assert_eq!(o[1], "https://user:***@host/x");
    }

    /// argv 元素里的 `key=value` + 剩余命令同样原样保留。
    #[test]
    fn argv_kv_keeps_remainder() {
        let (o, _) = redact_argv(&argv(&["bash", "-c", "echo 'PASSWORD=x' && rm -rf /"]));
        assert_eq!(o[2], "echo 'PASSWORD=***' && rm -rf /");
    }

    /// 误伤检查：单独出现的 "password" 这个词、普通 URL、普通 key=value 都不得被打码。
    #[test]
    fn patterns_do_not_fire_without_a_credential() {
        for s in [
            "the password field is required",
            "password",
            "https://example.com/path?q=1",
            "PATH=/usr/bin:/bin",
            "tokenizer is fast",
            "https://x.dev/a:b",
        ] {
            assert_eq!(redact_text(s), s, "误伤: {}", s);
        }
    }
}
