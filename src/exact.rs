//! v0.3 §3.5 三级绑定：用 **argv 做 join key**，把"意图"和"实际执行"连起来。
//!
//! ```text
//! agent tool.call  Bash cmd="curl -s -m 3 http://127.0.0.1:9/"
//! runtime exec     /bin/bash argv=["bash","-c","curl -s -m 3 http://127.0.0.1:9/"]
//!                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!                                                      同一个字符串
//! ```
//!
//! 会话级绑定（binding.rs，一/二级）只回答"这堆进程是不是这个 agent 的"。它绑不上
//! "哪条内核事实属于哪次 tool.call" —— 所以时间线上到处都是 `?`。argv 是现成的
//! 桥：tool.call 里写下的命令行，和 exec 时内核看到的 argv，是**同一条命令**的两种
//! 记录。本模块就是这座桥。
//!
//! # 判定的全部规则（V03_PROMPT §2，实现即文档）
//!
//! 1. **时间窗**：exec 必须落在 tool.call **之后** 且不超过 [`EXEC_AFTER_CALL_NS`]
//!    （120s）。exec 早于 call 一律不认（时间倒流不是匹配）。
//! 2. **规则 D（整串子串）**：把 exec 的 argv 用单个空格 join，若其中出现 cmd
//!    整串，且**前后都在 token 边界上**（串首/串尾或空格），判命中，规则名
//!    `argv exact`。这一条覆盖 `bash -c "<cmd>"` / `sh -c "<cmd>"`。
//!    边界检查是必须的：`ls` 是 `lsblk` 的子串，少了边界就会把 `lsblk` 认成 `ls`。
//! 3. **规则 S（wrapper 载荷子串）**（v0.3.1）：exec 是 `bash`/`sh` 带 `-c` 时，
//!    cmd 常常**不是** argv 里一个独立的 token —— 真实的 Claude Code 走的是
//!    `bash -c "<长前缀>; <cmd>"`，cmd 陷在 `-c` 的载荷里面。此时在**未经截断**的
//!    载荷上做朴素子串包含（[`shell_c_payload`] 负责从 `-c -l X` / `-lc` 这些
//!    形态里定位载荷），命中记为 `argv substring`。
//!    故意不叫 exact：朴素子串会在引号里、注释里、heredoc 里命中，它只是"这条
//!    命令**出现在**载荷里"，不是"载荷就是这条命令"。
//! 4. **规则 G（复合命令分段）**（v0.3.1）：cmd 里有 `;` `&&` `||` `|` 时，
//!    按这些顶层操作符切成片段（引号内的操作符不切），**任意一段**按规则 T 的
//!    判据（basename 前提 + ≥80% 重叠）命中即可，规则名 `argv segment`。
//!    真实案例：cmd = `curl -s -m 3 http://127.0.0.1:9/ ; echo "exit=$?"`，
//!    与 curl 的 argv 只有 62.5% 重叠（整串判定失败），但第一段是 100%。
//! 5. **规则 T（token 重叠）**：把 cmd 交给手写的 POSIX 风格分词器（[`shlex_split`]），
//!    与 exec argv 逐 token 比：`basename(cmd[0]) == basename(argv[0])` 是**前提**
//!    （连名字都不一样就不是同一条命令），随后统计多元集交集（argv[0] 计 1 分），
//!    `pct = 命中数 * 100 / max(len(cmd_tokens), len(argv))`，
//!    `pct >= ` [`TOKEN_OVERLAP_PCT`]（80）判命中，规则名 `argv overlap NN%`。
//!    这一条覆盖"用户写 `echo hi`、内核看到 `execve("/bin/echo", ["echo","hi"])`"
//!    这种路径被 argv[0] 补全的常见情形。
//! 6. **优先级**：同一条 exec 同时满足多条时，按 `D > S > G > T` 取**最强**的那条
//!    进括号 —— 结论越硬，标签越硬。规则 G 只在 cmd **确实被切开成 ≥2 段**时参与，
//!    否则单段命令会抢在规则 T 前面把 `argv overlap 100%` 降级成 `argv segment`
//!    （同一件事，标签却变弱了）。
//! 7. **顺序**：同一条 exec 命中多个未认领 tool.call 时，**cmd 更长的先赢**，同长取
//!    **最早**。V03_PROMPT 写的是"earliest unmatched wins"；这里做了一处收紧并
//!    在 DESIGN.md §3.5 记明原因：规则 D 是子串判定，一条陈旧的短命令（`ls`）
//!    会永远挡住后面那条具体的（`ls -la`）。对**完全相同的命令**（重试场景，
//!    验收 #2）长度相等，仍然回落到最早优先 —— 与规范一致。
//! 8. **认领**：一条 tool.call 只会认领**一条** exec（`matched` 置位后不再参与）。
//!    这样重试的同一命令会按时间顺序一一对应，不会全挤到第一条上。
//!
//! # 打码（--redact）不会破坏匹配
//!
//! `--redact argv+content` 下 cmd 与 argv 两侧的敏感 token 都变成 `***`。
//! `***` 在规则 T 里当**通配符**用（对面有 token 就算命中），所以打码只降级
//! "我们能不能核对", 不会让整条链断掉。此时规则名仍然是 `argv overlap NN%`，
//! 绝不是 `argv exact`。
//!
//! # 诚实边界
//!
//!  - 匹配是**不是**会话隔离的：一次运行里若同时有两个会话，跨会话同名命令按同一
//!    套顺序规则裁决。v0.3 面向单工作负载（`-p` / `-C`），不做多会话仲裁。
//!  - cmd 被截断（`bash_cmd_max`）时规则 D 直接放弃（截断串是前缀，整串命中
//!    意味着我们在拿残缺信息冒充完整匹配）；规则 T 仍然可用，但末尾那个被切断的
//!    token 按**前缀**参与比对，且规则名降级成 `argv prefix NN%`。argv 里我们
//!    没看见的 token 照常进分母，所以"看得越少，百分比越低"。
//!  - 同一理由，规则 S 在**载荷本身被内核截断**时放弃：`ls` 会命中 `lsblk` 被切剩的
//!    `ls`。规则 G 只跳过**截断点所在的那一段**，它前面的段是完整的，照样能用。
//!  - 规则 S 有个现实约束：内核侧单串上限 64 字节（见 `collector::bpftrace::MAX_STRLEN`），
//!    而真实 Claude Code 的 bash 包装前缀（`source .../snapshot-*.sh && ...`）本身
//!    就超过 64 字节，cmd 根本进不了可见载荷 —— 所以**真实案例是靠规则 G 绑上的**，
//!    规则 S 覆盖的是前缀较短的那些 wrapper（`bash -c "cd /x && make"`、`eval '<cmd>'`）。
//!    宁可规则 S 不触发，也不能为了让它触发去把截断说成全量。
//!  - 一条 exec 若已经因为属于某个已绑定进程的子树而被隐含标 exact，它**不会**
//!    再消耗一条 tool.call（先到先得，见 [`ExactBinder::on_exec`]）。

use crate::event::{Binding, Corr, Event, Kind, Layer, Payload};
use crate::redact::MASK;
use std::collections::{HashMap, HashSet};

/// exec 必须落在 tool.call **之后**的这个窗口内才可能被认领。
///
/// 120s 的取舍：比任何合理的单次工具调用都长（含 `sleep 110` 这种），又远短于
/// "同一个命令半小时后被人在另一个上下文里再跑一次"。窗口只在**匹配**时被用到，
/// 所以调大它只会增加误配，不会丢事件。
pub const EXEC_AFTER_CALL_NS: u64 = 120 * 1_000_000_000;

/// 规则 T 的通过阈值（百分比）。
///
/// 80 的取舍：`bash -c "<cmd>"` 有规则 D 兜底，规则 T 主要服务"路径补全 + 原样参数"
/// 这一类。实测在真实 transcript 上，正确的匹配几乎都落在 100%，而把阈值降到
/// 60 会开始把 `pytest -x tests/a.py` 认成 `pytest -x tests/b.py` 这种同工具不同
/// 目标的调用（都有 pytest，token 重叠 50%+）。80 在"漏"和"错"之间偏向不漏不错。
pub const TOKEN_OVERLAP_PCT: u32 = 80;

/// 一条 exec 最多可能认领的候选数（防病态输入把 O(n·m) 拉爆）。
/// 超出后只看最近的这么多条未认领调用 —— 老调用早该超时了。
const MAX_PENDING_CALLS: usize = 4096;

// ---------------------------------------------------------------------------
// 分词
// ---------------------------------------------------------------------------

/// POSIX 风格的命令行分词（等价于 Python 的 `shlex.split(comments=False)`）。
///
/// 支持单引号（内部全字面）、双引号（内部 `\` 只转义 `"` `\` `$` `` ` `` 换行）、
/// 引号外反斜杠转义、以及空参数 `""`（产出空串而不是被吃掉）。
///
/// **绝不 panic**：未闭合的引号按"到串尾为止"处理，并把 `unterminated` 置 true
/// 交给调用方 —— 截断的 cmd 正好会走到这条路径（铁律：解析器不 panic）。
pub fn shlex_split(s: &str) -> (Vec<String>, bool) {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut started = false; // 区分 `""`（空参数）与"还没开始"
    let mut unterminated = false;
    let mut it = s.chars();

    while let Some(c) = it.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                let mut closed = false;
                for c2 in it.by_ref() {
                    if c2 == '\'' {
                        closed = true;
                        break;
                    }
                    cur.push(c2);
                }
                if !closed {
                    unterminated = true;
                }
            }
            '"' => {
                started = true;
                let mut closed = false;
                while let Some(c2) = it.next() {
                    match c2 {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match it.next() {
                            Some(c3) if matches!(c3, '"' | '\\' | '$' | '`' | '\n') => cur.push(c3),
                            // 双引号里对其它字符的 `\` 是字面反斜杠（POSIX）。
                            Some(c3) => {
                                cur.push('\\');
                                cur.push(c3);
                            }
                            None => cur.push('\\'),
                        },
                        c2 => cur.push(c2),
                    }
                }
                if !closed {
                    unterminated = true;
                }
            }
            '\\' => {
                started = true;
                match it.next() {
                    Some(c2) => cur.push(c2),
                    // 末尾孤零零一个 `\`：POSIX 里它是续行符，但这里没有下一行可续。
                    // **保留它**而不是悄悄丢掉 —— 少一个字符就是少了一条证据，
                    // 而这个 token 还要拿去和内核 argv 比对。
                    None => cur.push('\\'),
                }
            }
            c => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        out.push(cur);
    }
    (out, unterminated)
}

/// 取路径的 basename（`/bin/echo` → `echo`）。与 collapse.rs 的 `basename` 同义，
/// 但这里要处理 `***`：打码后的 token 不能参与名字比较。
fn basename(p: &str) -> &str {
    let b = p.rsplit('/').next().unwrap_or(p);
    if b.is_empty() { p } else { b }
}

fn is_masked(tok: &str) -> bool {
    tok == MASK
}

// ---------------------------------------------------------------------------
// 判定规则
// ---------------------------------------------------------------------------

/// 命中的规则。规则名会**原样**进渲染的括号，所以这里不允许出现"看起来像精确"的
/// 模糊规则名（V03_PROMPT §3：Never claim "exact" for a fuzzy match）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleHit {
    /// 规则 D：边界感知的整串子串命中。
    Direct,
    /// 规则 S（v0.3.1）：cmd 是 `bash -c` 载荷的朴素子串。
    Substring,
    /// 规则 G（v0.3.1）：复合命令里**某一段**按规则 T 命中。
    Segment,
    /// 规则 T：token 重叠 `pct`%。`truncated` 表示 cmd 侧被截断、末尾 token 已丢弃。
    Tokens { pct: u32, truncated: bool },
}

impl RuleHit {
    /// 渲染进 `(...)` 的规则名 —— 必须与真实用上的判定一致。
    pub fn text(self) -> String {
        match self {
            RuleHit::Direct => "argv exact".to_string(),
            RuleHit::Substring => "argv substring".to_string(),
            RuleHit::Segment => "argv segment".to_string(),
            RuleHit::Tokens { pct, truncated: false } => format!("argv overlap {}%", pct),
            RuleHit::Tokens { pct, truncated: true } => format!("argv prefix {}%", pct),
        }
    }
}

/// 边界感知的整串包含：`hay` 中是否出现 `needle`，且 `needle` 两侧都在 token 边界。
///
/// 只认空格做边界（不做"标点也算边界"这种自作聪明）——内核给的 argv join 用空格，
/// 引用被 shell 吃掉之后剩下的就只有空格分隔。
fn contains_tokenwise(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    if nb.len() > hb.len() {
        return false;
    }
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let at = from + rel;
        let end = at + nb.len();
        // 前面是串首或空格；后面是串尾或空格。字节比较是安全的：
        // 空格/串边界都是 ASCII，不会切在多字节字符中间。
        let ok_before = at == 0 || hb[at - 1] == b' ';
        let ok_after = end == hb.len() || hb[end] == b' ';
        if ok_before && ok_after {
            return true;
        }
        from = at + 1;
        if from >= hay.len() {
            break;
        }
    }
    false
}

/// 规则 T 的核心：token 多元集重叠百分比。
///
/// `cmd_truncated` 为真时，cmd 的**最后一个** token 是残缺的（`bash_cmd_max` 从中间
/// 切断了它），于是它按**前缀**参与比对（`pool_token.starts_with(last_cmd_token)`），
/// 规则名也随之降级为 `argv prefix NN%` —— 我们核对过的确实只是前缀，不能念成
/// `exact`。分母取 `max(已知 token 数, argv 长度)`：截断让"已知"变少，argv 里那些
/// 我们没看见的 token 会把百分比拉下来，这正是"看不见的部分不许算作证据"。
///
/// 返回 `(pct, truncated_applied)`；`None` 表示前提不成立（argv 为空 / 名字不同）。
fn token_overlap(cmd_tokens: &[String], cmd_truncated: bool, argv: &[String]) -> Option<(u32, bool)> {
    if argv.is_empty() || cmd_tokens.is_empty() {
        return None;
    }
    let tc: Vec<&str> = cmd_tokens.iter().map(|s| s.as_str()).collect();
    let last = tc.len() - 1;
    // 只有一个 token 时它是命令名而不是参数：名字走的是精确比较（下面那关），
    // 前缀匹配不能用在命令名上（`ls` 前缀命中 `lsblk` 就是这一条要防的事）。
    let prefix_at = if cmd_truncated && tc.len() >= 2 {
        Some(last)
    } else {
        None
    };

    // 前提：命令名同 basename。打码 token 无法比较 → 放行（见模块头注释）。
    let n_cmd = basename(tc[0]);
    let n_arg = basename(&argv[0]);
    if !is_masked(n_cmd) && !is_masked(n_arg) && n_cmd != n_arg {
        return None;
    }

    let mut matched: u32 = 1; // argv[0] 已经在前提里核对过
    let mut pool: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();
    for (i, t) in tc[1..].iter().enumerate() {
        let idx = i + 1;
        let prefix_here = prefix_at == Some(idx);
        if is_masked(t) {
            // 打码 token：对面还有 token 就算命中（哪个都行），没有则不硬凑。
            if !pool.is_empty() {
                pool.remove(0);
            } else {
                continue;
            }
            matched += 1;
            continue;
        }
        let hit = pool
            .iter()
            .position(|x| *x == *t || is_masked(x) || (prefix_here && !t.is_empty() && x.starts_with(t)));
        if let Some(i) = hit {
            pool.remove(i);
            matched += 1;
        }
    }
    let denom = tc.len().max(argv.len()) as u32;
    if denom == 0 {
        return None;
    }
    Some((matched * 100 / denom, prefix_at.is_some()))
}

/// 在一行 shell 命令里切出**顶层**片段，按 `;` `&&` `||` `|` 切。
///
/// 引号内的分隔符不算数：`echo "a;b"` / `echo 'x|y'` 各自是一段。反斜杠转义的分隔符
/// 同样不算。`$(...)`、反引号、`{ ...; }` 这些嵌套结构**不做解析** —— 本函数只服务
/// "把复合命令拆开去和内核 argv 对齐"，多切一刀只会**少**一个候选片段，不会造出假
/// 匹配：每一段都还要各自过 basename 前提 + 80% 重叠。
///
/// 单独的 `&`（后台执行）按规范不在切割集里，原样保留。
fn split_segments(cmd: &str) -> Vec<String> {
    #[derive(PartialEq)]
    enum Q {
        None,
        Single,
        Double,
    }
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut q = Q::None;
    let mut it = cmd.chars().peekable();
    while let Some(c) = it.next() {
        match q {
            Q::None => match c {
                // 转义字符连同被转义的字符一起吞掉：`\;` 不是分隔符。
                '\\' => {
                    cur.push(c);
                    if let Some(n) = it.next() {
                        cur.push(n);
                    }
                }
                '\'' => {
                    q = Q::Single;
                    cur.push(c);
                }
                '"' => {
                    q = Q::Double;
                    cur.push(c);
                }
                ';' => out.push(std::mem::take(&mut cur)),
                '&' => {
                    if it.peek() == Some(&'&') {
                        it.next();
                        out.push(std::mem::take(&mut cur));
                    } else {
                        cur.push(c);
                    }
                }
                '|' => {
                    if it.peek() == Some(&'|') {
                        it.next();
                    }
                    out.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            },
            Q::Single => {
                // 单引号里除了配对的单引号，一切都是字面量（含 `\`）。
                if c == '\'' {
                    q = Q::None;
                }
                cur.push(c);
            }
            Q::Double => {
                if c == '\\' {
                    cur.push(c);
                    if let Some(n) = it.next() {
                        cur.push(n);
                    }
                } else {
                    if c == '"' {
                        q = Q::None;
                    }
                    cur.push(c);
                }
            }
        }
    }
    out.push(cur);
    out
}

/// 把 shell 命令按 `;` / `&&` / `||` / 换行切成子命令（引号感知）。
///
/// 和 `split_segments` 的区别：**不切管道符 `|`** —— 管道是 download-and-execute
/// 类模式（`*curl * | *sh*`）的结构本身，切掉就没法判断了。
///
/// 用途：watchlist 的 Bash 规则按子命令逐条匹配，避免 `*` 横跨 `;` 把几条不相干
/// 的子命令拼成一条"证据"。实测误报（2026-10-11）：中文 echo 里的 "curl" +
/// `| grep` 的管道符 + 单词 "dsh" 里的 "sh"，分属三条子命令，被整串匹配拼中。
pub(crate) fn split_commands(cmd: &str) -> Vec<String> {
    #[derive(PartialEq)]
    enum Q {
        None,
        Single,
        Double,
    }
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut q = Q::None;
    let mut it = cmd.chars().peekable();
    while let Some(c) = it.next() {
        match q {
            Q::None => match c {
                '\\' => {
                    cur.push(c);
                    if let Some(n) = it.next() {
                        cur.push(n);
                    }
                }
                '\'' => {
                    q = Q::Single;
                    cur.push(c);
                }
                '"' => {
                    q = Q::Double;
                    cur.push(c);
                }
                ';' | '\n' => out.push(std::mem::take(&mut cur)),
                '&' => {
                    if it.peek() == Some(&'&') {
                        it.next();
                        out.push(std::mem::take(&mut cur));
                    } else {
                        cur.push(c);
                    }
                }
                '|' => {
                    if it.peek() == Some(&'|') {
                        it.next();
                        out.push(std::mem::take(&mut cur));
                    } else {
                        cur.push(c);
                    }
                }
                _ => cur.push(c),
            },
            Q::Single => {
                if c == '\'' {
                    q = Q::None;
                }
                cur.push(c);
            }
            Q::Double => {
                if c == '\\' {
                    cur.push(c);
                    if let Some(n) = it.next() {
                        cur.push(n);
                    }
                } else {
                    if c == '"' {
                        q = Q::None;
                    }
                    cur.push(c);
                }
            }
        }
    }
    out.push(cur);
    out
}

/// exec 是 `bash`/`sh` 且带 `-c` 时，定位 `-c` 后面那个**命令字符串**在 argv 里的下标。
///
/// 要认的形态（前两种本机实测出现过）：
///   * `bash -c "<cmd>"`        → `-c` 后第一个操作数
///   * `bash -c -l SNAPSHOT=x`  → `-c` 之后仍可跟选项，第一个**非选项**才是命令串
///   * `bash -lc "<cmd>"`       → 短选项簇里含 `c` 也算
///   * `bash script.sh`         → 没有 `-c` → `None`（命令串根本不在 argv 里）
fn shell_c_payload(argv: &[String]) -> Option<usize> {
    if argv.is_empty() {
        return None;
    }
    let base = basename(&argv[0]);
    if !matches!(base, "bash" | "sh" | "dash" | "zsh" | "ksh") {
        return None;
    }
    let mut seen_c = false;
    for (i, a) in argv.iter().enumerate().skip(1) {
        if !seen_c {
            if a == "--" {
                continue;
            }
            // `-c` 本身，或 `-lc` / `-ec` 这类短选项簇（`a[1..]` 从 ASCII `-` 之后开始，
            // 不会切在多字节字符中间）。
            if a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c')) {
                seen_c = true;
                continue;
            }
            if a.starts_with('-') {
                continue;
            }
            // `-c` 之前的第一个操作数是脚本文件名：命令串不在 argv 里。
            return None;
        }
        // `-c` 之后：跳过剩余选项，第一个操作数就是命令串。
        if a.starts_with('-') && a != "-" {
            continue;
        }
        return Some(i);
    }
    None
}

/// 对一条 tool.call 的 cmd 和一条 exec 的 argv 跑完全部规则，返回命中的那一条。
///
/// 优先级 `D > S > G > T`（V03_PROMPT §2：exact > substring > segment > overlap）。
/// `argv_truncated` 列出 argv 里**已知被内核截断**的下标（来自事件的 `trunc` 说明），
/// 规则 S 会避开这些下标：截断串的前缀会让 `ls` 命中 `lsblk` 切剩的 `ls`。
pub fn match_rule(cmd: &str, cmd_truncated: bool, argv: &[String], argv_truncated: &[usize]) -> Option<RuleHit> {
    if cmd.is_empty() || argv.is_empty() {
        return None;
    }
    // 规则 D：整串。cmd 被截断时放弃 —— 前缀命中不等于完整命中。
    if !cmd_truncated {
        let joined = argv.join(" ");
        if contains_tokenwise(&joined, cmd) {
            return Some(RuleHit::Direct);
        }
        // 规则 S：cmd 陷在 `bash -c` 的载荷里。
        if let Some(i) = shell_c_payload(argv) {
            if !argv_truncated.contains(&i) && argv[i].contains(cmd) {
                return Some(RuleHit::Substring);
            }
        }
    }
    // 规则 G：复合命令的某一段单独命中。只在真的被切开（≥2 段）时参与，
    // 否则单段命令会把规则 T 的 `argv overlap NN%` 无谓降级成 `argv segment`。
    let segs = split_segments(cmd);
    if segs.len() >= 2 {
        let last = segs.len() - 1;
        for (i, seg) in segs.iter().enumerate() {
            // 截断点落在最后一段里 → 那一段是残缺的，不拿它当证据。
            if (cmd_truncated && i == last) || seg.trim().is_empty() {
                continue;
            }
            let (tokens, unterminated) = shlex_split(seg);
            if let Some((pct, _)) = token_overlap(&tokens, unterminated, argv) {
                if pct >= TOKEN_OVERLAP_PCT {
                    return Some(RuleHit::Segment);
                }
            }
        }
    }
    // 规则 T。
    let (tokens, unterminated) = shlex_split(cmd);
    let (pct, trunc) = token_overlap(&tokens, cmd_truncated || unterminated, argv)?;
    if pct >= TOKEN_OVERLAP_PCT {
        Some(RuleHit::Tokens { pct, truncated: trunc })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// 绑定器
// ---------------------------------------------------------------------------

/// 一条已记录、等待认领的 tool.call。
#[derive(Debug, Clone)]
struct PendingCall {
    session_id: Option<String>,
    tool_use_id: Option<String>,
    tool: String,
    cmd: String,
    /// cmd 是否被 `bash_cmd_max` 截断（截断则降级到 `argv prefix`）。
    cmd_truncated: bool,
    ts_ns: u64,
    matched: bool,
}

/// 一个进程的绑定结果。
///
/// 只留 `tool_use_id`：它是**影响渲染与 JSON** 的那一份信息（`?` 消失、
/// 内核行带上 join key）。规则名只服务于那一行 bind 证据，不进每个进程。
#[derive(Debug, Clone)]
struct Bound {
    tool_use_id: Option<String>,
}

/// v0.3 的绑定统计（进 `--output json` 的 summary 与 `-v` 诊断）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BindStats {
    /// 记录下来的 shell 命令 tool.call 数（只有带命令的才计数）。
    pub calls_seen: u64,
    /// 被 exec 认领的 tool.call 数。
    pub calls_matched: u64,
    /// 见到的 exec 事件数。
    pub execs_seen: u64,
    /// 被标成 `exact` 的进程数（含子树，按 pid 去重）。
    pub pids_exact: u64,
    /// 用规则 D 命中的次数。
    pub by_direct: u64,
    /// 用规则 S 命中的次数。
    pub by_substring: u64,
    /// 用规则 G 命中的次数。
    pub by_segment: u64,
    /// 用规则 T 命中的次数。
    pub by_tokens: u64,
    /// 派生的 bind 行数（= `calls_matched`，单独列出来是给"行数对得上"用）。
    pub derived_rows: u64,
}

/// argv 级绑定器。**批次处理**：merger 交出一批已排序事件，本模块跑两遍。
///
/// 为什么要两遍：fork 行说的是"父进程创建了 pid N"，而"pid N 被绑定"这件事
/// 要等同一批里的 exec 行才成立。一遍过会让 fork 行永远比它的子进程晚一步知道
/// 自己该不该标 `exact`（streaming 场景下批次只有几十毫秒，一行之差就是
/// "echo 的 fork 行没有 `=` 但 exec 行有"，看起来像 bug）。两遍的代价是把一批
/// 事件在内存里多放一次 —— 批次是 merger 的 200ms 窗口，量级完全可控。
#[derive(Debug)]
pub struct ExactBinder {
    enabled: bool,
    /// 未认领 / 已认领的 tool.call，按时间追加（只增不删：一条已认领的调用还要
    /// 参与"这条 agent 行能不能升级为 exact"的判断）。
    calls: Vec<PendingCall>,
    /// 已认领调用的 tool_use_id，用于给**后到的** agent 行（tool.result）升级。
    matched_ids: HashSet<String>,
    /// pid → 绑定结果。第一次绑定胜出，之后不再改写。
    bound: HashMap<u32, Bound>,
    /// 观察到的 fork 关系：ppid → children（只用于把绑定传给子树）。
    children: HashMap<u32, Vec<u32>>,
    /// **暂缓一批**的行（见 [`ExactBinder::process`]）：本批从第一条未定论的 fork 行
    /// 起、到批末的整段后缀，外加挂在这些行后面的 bind 派生行。
    ///
    /// 只从上一次 `process()` 带过来，量级就是 merger 一个窗口的行数；下一批开头
    /// 无条件放行，所以它不会无限增长，也不会让某一行永远不出现。
    held: Vec<Event>,
    pub stats: BindStats,
}

impl ExactBinder {
    /// `enabled=false`（`--no-bind`）时 [`process`](Self::process) 原样返回，
    /// 一个字节都不动 —— 这是 v0.3 前后对比证据能复现的基础。
    ///
    /// 注意：会话级绑定等级（agent 行的 `binding`）**不由本模块负责**，main 直接盖。
    /// 本模块只做"tool.call 级的证据"，两者不要在代码里混成一处，否则 `--no-bind`
    /// 一关就会把整个 §3.5 降级链一起关掉。
    pub fn new(enabled: bool) -> Self {
        ExactBinder {
            enabled,
            calls: Vec::new(),
            matched_ids: HashSet::new(),
            bound: HashMap::new(),
            children: HashMap::new(),
            held: Vec::new(),
            stats: BindStats::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn stats(&self) -> BindStats {
        self.stats
    }

    /// 一个批次的处理入口。`events` 必须是 merger 给出的**时间有序**批次。
    ///
    /// 返回值可能比输入长（插入 bind 派生行），顺序保持时间有序：
    /// 派生行紧跟在它解释的那条 exec 之后（同 ts，与 collapse.rs 的做法一致）。
    ///
    /// # 为什么 fork 行要暂缓一批
    ///
    /// 一条 fork 行说的是"我创建了 pid N"，而"pid N 是否属于某次 tool.call"要等
    /// **N 自己 exec 之后**才有答案。实测（验收 #1 第一次跑）：fork 与 exec 相隔 7ms，
    /// 而 merger 的 `take_ready()` 完全可能正好切在中间 —— 那一批里 fork 行先被渲染，
    /// 于是它显示"未绑定"，7ms 后它的子进程的 exec 行却带着 `=`。读者看到的是一对
    /// 自相矛盾的行，而这正是本工具最不该犯的错（§4.3：不许说不知道以外的话，
    /// 也不许说半句话）。
    ///
    /// 处理方式与 v0.2 的折叠器同源：**先定论，再渲染**。子进程还没绑定就把 fork 行
    /// 留下一批，下一批开头它已经被 `pass 1` 判过了 —— 到那时再盖章。代价是这些行晚
    /// 一个 poll 周期出现（≤ 一个 merger 窗口），而它们本来就在 200ms 的重排窗口里
    /// 等过一轮。
    ///
    /// # 为什么暂缓的是**一段后缀**而不是单独一行
    ///
    /// 暂缓一行、放行它后面的行会**破坏时间序**：被暂缓的 fork 行比同批它后面的行旧，
    /// 却晚一批才出现，于是读者看到 `exec curl` 排在 `fork -> curl` 前面（v0.3 第一版
    /// 的实测缺陷，见 BUILD_LOG §15.4）。所以从第一条未定论的 fork 行起，**直到批末
    /// 的整段一起暂缓**，放回下一批队首 —— 全局有序性因此严格保持。
    ///
    /// 挂在这段后缀里的 bind 派生行（`inserted`）必须跟着一起走，否则它们会被丢掉：
    /// 一段后缀完全可能包含产生 bind 行的 exec 行。
    pub fn process(&mut self, events: Vec<Event>) -> Vec<Event> {
        if !self.enabled {
            return events;
        }
        // 上一批暂缓的后缀排在最前（它们更旧，放队首才不破坏时间序）。
        let carried_n = self.held.len();
        let mut all = std::mem::take(&mut self.held);
        all.extend(events);
        if all.is_empty() {
            return all;
        }
        // ---- pass 1：推进状态、做判决、生成派生行 ----
        //
        // 只跑本批**新来的**行（`i >= carried_n`）。带过一批的行在上一批的 pass 1
        // 里已经推进过一次状态了：再跑一次会把同一条 tool.call 再入队一份
        // （`on_tool_call` 不是幂等的），于是它的副本会去认领第二条 exec，
        // 把一个无关的 pid 标成 `exact`；`calls_seen` / `execs_seen` 也会一起翻倍。
        // pass 2 对暂缓段的处理本来就是"不再重新判定、只重新盖章"（见下），
        // 两遍的边界在这里必须一致。
        let mut inserted: HashMap<usize, Vec<Event>> = HashMap::new();
        for (i, ev) in all.iter().enumerate().skip(carried_n) {
            match ev.kind {
                Kind::AgentToolCall => self.on_tool_call(ev),
                Kind::RuntimeProcExec => {
                    self.stats.execs_seen += 1;
                    self.on_exec(i, ev, &mut inserted);
                }
                Kind::RuntimeProcFork => self.on_fork(ev),
                _ => {}
            }
        }
        // ---- pass 2：盖章（用批次的最终状态）+ 插行 ----
        let mut out = Vec::with_capacity(all.len() + inserted.len());
        // 本批第一条"未定论"的 fork 行的下标；它之后的**所有**行一起暂缓。
        let mut hold_from: Option<usize> = None;
        for (i, mut ev) in all.into_iter().enumerate() {
            self.stamp(&mut ev);
            // 只对本批新来的行判定（i >= carried_n）；带过一批的（i < carried_n）
            // 无条件放行：子进程可能早就退出了，再留下去就是"永远不出现"，
            // 比"晚一批"糟得多。
            if hold_from.is_none() && i >= carried_n && ev.kind == Kind::RuntimeProcFork && ev.binding != Binding::Exact
            {
                hold_from = Some(i);
            }
            if hold_from.is_some_and(|h| i >= h) {
                self.held.push(ev);
                // 派生行跟着它解释的那条 exec 一起走（见方法注释）。
                if let Some(rows) = inserted.remove(&i) {
                    self.held.extend(rows);
                }
                continue;
            }
            out.push(ev);
            if let Some(rows) = inserted.remove(&i) {
                out.extend(rows);
            }
        }
        out
    }

    /// 流结束：把暂缓的后缀交出来（再等也不会有新的 exec 了）。
    ///
    /// 调用方必须**先** `process()` 再 `finish()`，并把 `finish()` 的行放在那一批的
    /// **后面**：`process()` 已经把上一批的暂缓段放行在前，`finish()` 交出的是**最后
    /// 一批的尾巴**，也就是整条流里最新的行。
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.held);
        for ev in out.iter_mut() {
            self.stamp(ev);
        }
        out
    }

    /// 给一条事件盖上 `binding`。
    ///
    /// agent 行的会话级等级由 main 在产出时就盖好了（`--no-bind` 下也一样），
    /// 这里只在**有 tool.call 级证据**时把它升级成 `exact` —— 后到的 tool.result
    /// 属于一条已认领的调用时，整次工具调用就闭环了。
    fn stamp(&self, ev: &mut Event) {
        if ev.layer == Layer::Agent {
            if let Some(id) = ev.corr.tool_use_id.as_deref() {
                if self.matched_ids.contains(id) {
                    ev.binding = Binding::Exact;
                }
            }
            return;
        }
        if ev.binding == Binding::Exact {
            return; // 派生行自带（bind 行说的就是绑定本身），别覆盖
        }
        // 内核行：pid 在表里 → exact，并把 tool_use_id 补进 corr（V03_PROMPT §5 的 join key）。
        if let Some(b) = ev.pid.and_then(|p| self.bound.get(&p)) {
            ev.binding = Binding::Exact;
            if ev.corr.tool_use_id.is_none() {
                ev.corr.tool_use_id = b.tool_use_id.clone();
            }
            return;
        }
        // 还是没绑上：fork 行说的是"我创建了被绑定的子进程"，它属于这条链。
        if let Payload::ProcFork { child_pid, .. } = &ev.payload {
            if let Some(b) = self.bound.get(child_pid) {
                ev.binding = Binding::Exact;
                if ev.corr.tool_use_id.is_none() {
                    ev.corr.tool_use_id = b.tool_use_id.clone();
                }
            }
        }
    }

    /// 变更 1：记下带 shell 命令的 tool.call。
    fn on_tool_call(&mut self, ev: &Event) {
        let Payload::ToolCall { tool, bash_cmd, .. } = &ev.payload else {
            return;
        };
        // v0.3 只认 Bash 的 `command`/`cmd`（V03_PROMPT §1："start with Bash"）。
        // 其它工具的命令提取留给后续版本，宁缺毋滥：猜出来的命令行会直接变成
        // 一条 `exact` 断言。
        if !tool.eq_ignore_ascii_case("bash") {
            return;
        }
        let Some(cmd) = bash_cmd.as_deref().filter(|c| !c.trim().is_empty()) else {
            return;
        };
        if self.calls.len() >= MAX_PENDING_CALLS {
            // 病态输入（几千条 tool.call 而内核一条 exec 都没有）：丢最老的。
            self.calls.remove(0);
        }
        let truncated = ev.trunc.iter().any(|t| t.field == "bash_cmd");
        self.calls.push(PendingCall {
            session_id: ev.corr.session_id.clone(),
            tool_use_id: ev.corr.tool_use_id.clone(),
            tool: tool.clone(),
            cmd: cmd.to_string(),
            cmd_truncated: truncated,
            ts_ns: ev.ts_ns,
            matched: false,
        });
        self.stats.calls_seen += 1;
    }

    /// 变更 2：exec 到来时找一条未认领的 tool.call。
    fn on_exec(&mut self, at: usize, ev: &Event, inserted: &mut HashMap<usize, Vec<Event>>) {
        let Payload::ProcExec { filename, argv, .. } = &ev.payload else {
            return;
        };
        let Some(pid) = ev.pid else { return };
        // argv 缺失（内核侧 stash 丢了）时不猜：没有 join key 就没有匹配。
        if argv.is_empty() || self.calls.is_empty() {
            return;
        }
        // 已经因为"属于某个已绑定进程的子树"而必须是 exact 的进程，
        // 不再消耗一条 tool.call —— 一条调用只对应一条 exec。
        if self.bound.contains_key(&pid) {
            return;
        }

        // argv 里被内核截断的下标（`argv[2]` 这种）。规则 S 要避开它们：
        // 载荷只剩前缀时，`ls` 会命中 `lsblk` 被切剩的 `ls`。
        let argv_trunc: Vec<usize> = ev
            .trunc
            .iter()
            .filter_map(|t| t.field.strip_prefix("argv[")?.strip_suffix(']')?.parse().ok())
            .collect();

        let mut best: Option<(usize, RuleHit, u64)> = None;
        for (ci, c) in self.calls.iter().enumerate() {
            if c.matched {
                continue;
            }
            if ev.ts_ns < c.ts_ns {
                continue; // exec 早于 call：时间倒流，不认
            }
            let delta = ev.ts_ns - c.ts_ns;
            if delta > EXEC_AFTER_CALL_NS {
                continue; // 超出时间窗
            }
            let Some(hit) = match_rule(&c.cmd, c.cmd_truncated, argv, &argv_trunc) else {
                continue;
            };
            let better = match &best {
                None => true,
                // 更长的 cmd 更具体；完全相同则保留先到的（最早优先）。
                Some((bi, _, _)) => c.cmd.chars().count() > self.calls[*bi].cmd.chars().count(),
            };
            if better {
                best = Some((ci, hit, delta));
            }
        }
        let Some((ci, hit, delta)) = best else { return };

        let rule_text = hit.text();
        self.calls[ci].matched = true;
        let tool = self.calls[ci].tool.clone();
        let cmd = self.calls[ci].cmd.clone();
        let cmd_truncated = self.calls[ci].cmd_truncated;
        let tool_use_id = self.calls[ci].tool_use_id.clone();
        let session_id = self.calls[ci].session_id.clone();
        self.stats.calls_matched += 1;
        match hit {
            RuleHit::Direct => self.stats.by_direct += 1,
            RuleHit::Substring => self.stats.by_substring += 1,
            RuleHit::Segment => self.stats.by_segment += 1,
            RuleHit::Tokens { .. } => self.stats.by_tokens += 1,
        }
        if let Some(id) = &tool_use_id {
            self.matched_ids.insert(id.clone());
        }

        let info = Bound {
            tool_use_id: tool_use_id.clone(),
        };
        let subtree = self.bind_pid(pid, info, true);
        self.stats.derived_rows += 1;

        let row = bind_event(
            ev,
            pid,
            &tool,
            &cmd,
            cmd_truncated,
            filename,
            &rule_text,
            tool_use_id,
            session_id,
            delta,
            subtree,
        );
        inserted.entry(at).or_default().push(row);
    }

    /// 变更 3 的一半：把一个 pid（`scan_descendants` 为真时连它的**已知子树**）
    /// 标成已绑定，并沿着观察到的 fork 关系继续往下传。
    ///
    /// `scan_descendants` 只在"这个 pid 就是被匹配到的 exec 进程"时为真：
    /// 它会扫一遍 `/proc`，代价不小，而只有这一次扫描才可能捞到**我们 attach 之前
    /// 就存在**的后代（一个先 fork 再 exec 的进程，它的孩子在我们眼里是凭空出现的）。
    /// 后续继承的子进程不需要再扫（它们的子树会被 fork 事件补齐）。
    ///
    /// 返回这一跳新增的绑定进程数（含 `pid` 自己，若它是新绑定的）。
    fn bind_pid(&mut self, pid: u32, info: Bound, scan_descendants: bool) -> u64 {
        let mut added = 0u64;
        if !self.bound.contains_key(&pid) {
            self.bound.insert(pid, info.clone());
            self.stats.pids_exact += 1;
            added += 1;
        }
        if scan_descendants {
            for p in crate::collector::bpftrace::scan_descendants(pid) {
                if p == pid || self.bound.contains_key(&p) {
                    continue;
                }
                self.bound.insert(p, info.clone());
                self.stats.pids_exact += 1;
                added += 1;
            }
        }
        // 沿已观察到的 fork 关系把绑定铺满整棵子树（含孙子）。
        let mut stack = vec![pid];
        let mut guard = 0usize;
        while let Some(p) = stack.pop() {
            guard += 1;
            if guard > 4096 {
                break; // 环路防御：fork 关系理论上无环，但别让坏数据把循环卡死
            }
            for c in self.children.get(&p).cloned().unwrap_or_default() {
                if !self.bound.contains_key(&c) {
                    self.bound.insert(c, info.clone());
                    self.stats.pids_exact += 1;
                    added += 1;
                    stack.push(c);
                }
            }
        }
        added
    }

    /// 记录 fork 关系；父进程已绑定则子进程继承。
    fn on_fork(&mut self, ev: &Event) {
        let (Some(parent), Payload::ProcFork { child_pid, .. }) = (ev.pid, &ev.payload) else {
            return;
        };
        let child = *child_pid;
        let kids = self.children.entry(parent).or_default();
        if !kids.contains(&child) {
            kids.push(child);
        }
        let inherited = self.bound.get(&parent).cloned();
        if let Some(info) = inherited {
            // 子进程继承绑定：它整条生命周期的内核事实都属于同一次 tool.call。
            self.bind_pid(child, info, false);
        }
    }
}

/// 构造 bind 派生行（变更 3 的后一半）。
///
/// ts/pid/comm 继承那条 exec（派生行必须落在它解释的事实的时间位置上），
/// 但 corr 用**新造的**：它要带的是被匹配上的 tool.call 的 session/tool_use_id，
/// 而不是内核行那个空的 corr。
#[allow(clippy::too_many_arguments)]
fn bind_event(
    exec: &Event,
    pid: u32,
    tool: &str,
    cmd: &str,
    cmd_truncated: bool,
    exec_filename: &str,
    rule: &str,
    tool_use_id: Option<String>,
    session_id: Option<String>,
    delta_ns: u64,
    subtree_pids: u64,
) -> Event {
    let delta_ms = delta_ns / 1_000_000;
    let mut notes = vec![format!(
        "tool.call matched to this exec by {} ({}ms after the call); pid {} and its subtree marked exact",
        rule, delta_ms, pid
    )];
    if subtree_pids > 1 {
        notes.push(format!(
            "{} process(es) in this subtree inherited binding=exact",
            subtree_pids
        ));
    }
    if cmd_truncated {
        // 自曝：这一行给出的命令行是**截断过**的，别拿它当完整命令读。
        notes.push(format!(
            "tool.call command was truncated at bash_cmd_max ({} bytes kept); rule fell back to the token comparison",
            cmd.len()
        ));
    }
    Event {
        seq: 0,
        ts_ns: exec.ts_ns,
        ts_wall_ns: exec.ts_wall_ns,
        ts_src: exec.ts_src,
        layer: Layer::Derived,
        kind: Kind::DerivedBind,
        source: "bind".into(),
        pid: Some(pid),
        tid: None,
        ppid: exec.ppid,
        comm: exec.comm.clone(),
        cgroup_id: None,
        corr: Corr {
            session_id,
            tool_use_id,
            ..Corr::default()
        },
        payload: Payload::Bind {
            tool: tool.to_string(),
            cmd_preview: cmd.to_string(),
            exec_filename: exec_filename.to_string(),
            rule: rule.to_string(),
            delta_ms,
            pid,
            subtree_pids,
        },
        trunc: Vec::new(),
        notes,
        late: false,
        watch: false,
        retry: false,
        // 这一行**就是** exact 断言本身（它由 argv 匹配产出），所以是 exact；
        // 但渲染层不会给它打 `=`（`=` 只给内核行），否则读者会以为它被绑到了别的行。
        binding: Binding::Exact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Corr, TsSource};

    const S: u64 = 1_000_000_000;

    fn argv_of(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// 一条 Bash tool.call。`trunc` 为真时附上 `bash_cmd` 的截断记录
    /// （与 adapter 的 `preview()` 产出的形态一致）。
    fn call(ts: u64, id: &str, cmd: &str, trunc: bool) -> Event {
        let t = if trunc {
            vec![crate::event::TruncNote::new("bash_cmd", Some(4096), cmd.len())]
        } else {
            Vec::new()
        };
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: ts,
            ts_src: TsSource::Converted,
            layer: Layer::Agent,
            kind: Kind::AgentToolCall,
            source: "claude-code".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr {
                session_id: Some("sess0001".into()),
                tool_use_id: Some(id.into()),
                ..Default::default()
            },
            binding: Binding::Heuristic,
            payload: Payload::ToolCall {
                tool: "Bash".into(),
                input_preview: "{}".into(),
                input_bytes: 2,
                via_mcp: false,
                bash_cmd: Some(cmd.into()),
            },
            trunc: t,
            notes: Vec::new(),
            late: false,
            watch: false,
            retry: false,
        }
    }

    fn exec(ts: u64, pid: u32, filename: &str, argv: &[&str]) -> Event {
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: ts,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: Kind::RuntimeProcExec,
            source: "kernel".into(),
            pid: Some(pid),
            tid: Some(pid),
            ppid: Some(1),
            comm: Some("prog".into()),
            cgroup_id: None,
            corr: Corr::default(),
            binding: Binding::None,
            payload: Payload::ProcExec {
                filename: filename.into(),
                argv: argv_of(argv),
                argc_total: Some(argv.len()),
            },
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: false,
            retry: false,
        }
    }

    fn fork(ts: u64, parent: u32, child: u32) -> Event {
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: ts,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: Kind::RuntimeProcFork,
            source: "kernel".into(),
            pid: Some(parent),
            tid: Some(parent),
            ppid: Some(1),
            comm: Some("parent".into()),
            cgroup_id: None,
            corr: Corr::default(),
            binding: Binding::None,
            payload: Payload::ProcFork {
                child_pid: child,
                child_comm: "child".into(),
                parent_argv: None,
            },
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: false,
            retry: false,
        }
    }

    fn run(binder: &mut ExactBinder, evs: Vec<Event>) -> Vec<Event> {
        binder.process(evs)
    }

    fn binds(out: &[Event]) -> Vec<&Event> {
        out.iter().filter(|e| e.kind == Kind::DerivedBind).collect()
    }

    // ---------------- 分词 ----------------

    #[test]
    fn shlex_handles_quotes_escapes_and_empty_args() {
        assert_eq!(shlex_split("a b c").0, vec!["a", "b", "c"]);
        assert_eq!(shlex_split("echo 'hi there'").0, vec!["echo", "hi there"]);
        assert_eq!(shlex_split("echo \"hi there\"").0, vec!["echo", "hi there"]);
        assert_eq!(shlex_split("a\\ b").0, vec!["a b"]);
        assert_eq!(shlex_split("x \"\"").0, vec!["x", ""]);
        assert_eq!(shlex_split("   ").0, Vec::<String>::new());
        // 双引号里对普通字符的 `\` 是字面反斜杠（POSIX）。
        assert_eq!(shlex_split("\"a\\nb\"").0, vec!["a\\nb"]);
        assert_eq!(shlex_split("\"a\\\"b\"").0, vec!["a\"b"]);
    }

    #[test]
    fn shlex_never_panics_on_unterminated_input() {
        // 铁律：解析器不 panic。截断的 cmd 正好长这样。
        let (v, un) = shlex_split("echo 'unterminated");
        assert_eq!(v, vec!["echo", "unterminated"]);
        assert!(un);
        let (v2, un2) = shlex_split("echo \"unterminated");
        assert_eq!(v2, vec!["echo", "unterminated"]);
        assert!(un2);
        // 结尾一个孤零零的反斜杠。
        let (v3, _) = shlex_split("echo \\");
        assert_eq!(v3, vec!["echo", "\\"]);
    }

    // ---------------- 规则 D / T ----------------

    #[test]
    fn rule_direct_matches_bash_c() {
        // V03_PROMPT 的原例：`bash -c "<cmd>"`。
        let cmd = "curl -s -m 3 http://127.0.0.1:9/";
        let argv = argv_of(&["bash", "-c", cmd]);
        let hit = match_rule(cmd, false, &argv, &[]).expect("must match");
        assert_eq!(hit, RuleHit::Direct);
        assert_eq!(hit.text(), "argv exact");
    }

    #[test]
    fn rule_direct_needs_a_token_boundary() {
        // `ls` 是 `lsblk` 的子串，但**不是**它的 token。
        assert!(match_rule("ls", false, &argv_of(&["lsblk"]), &[]).is_none());
        // 甚至不能因为前缀就认成同一个命令（basename 不同）。
        assert!(match_rule("cargo", false, &argv_of(&["cargo-nextest", "run"]), &[]).is_none());
    }

    #[test]
    fn rule_tokens_covers_path_completion() {
        // 用户写 `echo hi`，内核看到 `execve("/bin/echo", ["echo","hi"])`。
        let hit = match_rule(
            "echo hello-v03-bind",
            false,
            &argv_of(&["/bin/echo", "hello-v03-bind"]),
            &[],
        )
        .expect("must match");
        assert_eq!(
            hit,
            RuleHit::Tokens {
                pct: 100,
                truncated: false
            }
        );
        assert_eq!(hit.text(), "argv overlap 100%");
    }

    #[test]
    fn rule_tokens_rejects_below_threshold() {
        // 同工具、不同目标：2/3 = 66% < 80% → 不认。
        assert!(
            match_rule(
                "pytest -x tests/a.py",
                false,
                &argv_of(&["pytest", "-x", "tests/b.py"]),
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn rule_tokens_is_order_insensitive_but_name_checked() {
        // 参数顺序不同仍算命中（多元集比对）。
        let hit = match_rule(
            "git -C /repo status",
            false,
            &argv_of(&["/usr/bin/git", "status", "-C", "/repo"]),
            &[],
        )
        .expect("must match");
        assert_eq!(
            hit,
            RuleHit::Tokens {
                pct: 100,
                truncated: false
            }
        );
        // 名字不同 → 直接放弃，哪怕参数一模一样。
        assert!(
            match_rule(
                "rg --json foo",
                false,
                &argv_of(&["/usr/bin/grep", "--json", "foo"]),
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn multiline_and_quoted_commands_match_the_kernel_form() {
        // `bash -c $'a\nb'`：内核 argv 里是一个含真实换行的 token，
        // tool.call 侧是同一串（adapter 只做显示层 one_line，不改进 payload）。
        let cmd = "bash -c echo a\nb";
        let argv = argv_of(&["bash", "-c", "echo a\nb"]);
        assert_eq!(match_rule(cmd, false, &argv, &[]).expect("must match"), RuleHit::Direct);
    }

    #[test]
    fn masked_tokens_are_wildcards() {
        // --redact argv+content：两侧都被打码时，链不能因此断掉。
        let hit = match_rule(
            "curl -H Authorization: *** http://x/",
            false,
            &argv_of(&["/usr/bin/curl", "-H", "Authorization:", "***", "http://x/"]),
            &[],
        )
        .expect("must still match");
        assert!(
            matches!(hit, RuleHit::Tokens { .. }),
            "masked match must not claim `argv exact`"
        );
    }

    #[test]
    fn truncated_cmd_uses_prefix_rule_and_says_so() {
        // 真命令是 `deploy --target prod`，被 bash_cmd_max 切在最后一个 token 中间。
        let cmd = "deploy --target pro";
        let argv = argv_of(&["deploy", "--target", "prod"]);
        // 规则 D 放弃（截断串是前缀，不整串命中）。
        assert!(!contains_tokenwise(&argv.join(" "), cmd));
        let hit = match_rule(cmd, true, &argv, &[]).expect("prefix rule must match");
        // 三个 token 全部对上 —— 但**必须是** prefix，不能是 overlap/exact。
        assert_eq!(
            hit,
            RuleHit::Tokens {
                pct: 100,
                truncated: true
            }
        );
        assert_eq!(hit.text(), "argv prefix 100%");
    }

    #[test]
    fn truncation_that_hides_whole_tokens_refuses_to_match() {
        // 切掉了整整两个 token：我们只看见了内核 argv 的 3/5。
        // 分母把"没看见的"算进去 → 60% < 80%，宁可不认。
        let cmd = "deploy --target pro";
        let argv = argv_of(&["deploy", "--target", "prod", "--token", "SECRET"]);
        assert!(match_rule(cmd, true, &argv, &[]).is_none());
    }

    #[test]
    fn truncated_cmd_is_never_labelled_exact() {
        let cmd = "deploy --target pro";
        let argv = argv_of(&["deploy", "--target", "prod"]);
        let hit = match_rule(cmd, true, &argv, &[]).expect("must match");
        assert_ne!(hit.text(), "argv exact");
        assert!(hit.text().starts_with("argv prefix"), "got {}", hit.text());
    }

    // ---------------- 规则 S（wrapper 载荷子串） ----------------

    #[test]
    fn rule_substring_finds_cmd_inside_the_c_payload() {
        // 真实 Claude Code 形态：cmd 陷在 `-c` 载荷的长前缀后面，argv 里没有它的
        // 独立 token。规则 D 不命中（整串不在 join 里，前后没有空格边界）。
        let cmd = "curl -s -m 3 http://127.0.0.1:9/";
        let payload = format!("cd /work && set -o pipefail; eval '{}'", cmd);
        let argv = argv_of(&["/bin/bash", "-c", &payload]);
        assert!(!contains_tokenwise(&argv.join(" "), cmd), "规则 D 不该命中");
        let hit = match_rule(cmd, false, &argv, &[]).expect("must match");
        assert_eq!(hit, RuleHit::Substring);
        assert_eq!(hit.text(), "argv substring");
    }

    /// `bash -c -l SNAPSHOT_FILE=x` 是 snapshot 生成器的真实形态：`-c` 后面**还有**
    /// 选项，命令串是第一个非选项操作数。
    ///
    /// 注意这里必须有引号：载荷若是光秃秃的 `cd /tmp && make -j4`，join 之后
    /// `make -j4` 前后正好都是空格边界，规则 D 就命中了（那是更强的证据，
    /// 当然该由 D 拿下）。`eval '<cmd>'` 这种被引用包起来的形态才是规则 S 的靶子。
    #[test]
    fn rule_substring_skips_options_after_dash_c() {
        let argv = argv_of(&["/bin/bash", "-c", "-l", "cd /tmp && eval 'make -j4'"]);
        assert_eq!(shell_c_payload(&argv), Some(3));
        assert_eq!(
            match_rule("make -j4", false, &argv, &[]).map(|h| h.text()),
            Some("argv substring".to_string())
        );
    }

    #[test]
    fn shell_c_payload_forms() {
        let argv_of_ = |v: &[&str]| argv_of(v);
        // 合并短选项 `-lc`。
        assert_eq!(shell_c_payload(&argv_of_(&["bash", "-lc", "echo hi"])), Some(2));
        // 不是 `-c` 调用：命令串根本不在 argv 里。
        assert_eq!(shell_c_payload(&argv_of_(&["bash", "script.sh"])), None);
        // `-c` 在但后面没有操作数。
        assert_eq!(shell_c_payload(&argv_of_(&["bash", "-c"])), None);
        // 别的程序即便带 `-c` 也不算（`curl -c` 是 cookie jar）。
        assert_eq!(
            shell_c_payload(&argv_of_(&["curl", "-c", "jar.txt", "http://x/"])),
            None
        );
        // `--` 之后的操作数仍被当作脚本名（没有 `-c` → None）。
        assert_eq!(shell_c_payload(&argv_of_(&["sh", "--", "a.sh"])), None);
    }

    /// 载荷**本身**被内核截断时不许用规则 S：`ls` 会命中 `lsblk` 被切剩的 `ls`。
    #[test]
    fn rule_substring_refuses_when_the_payload_is_truncated() {
        let argv = argv_of(&["/bin/bash", "-c", "eval 'lsblk'"]);
        assert_eq!(
            match_rule("ls", false, &argv, &[]).expect("完整载荷可以命中").text(),
            "argv substring"
        );
        assert!(
            match_rule("ls", false, &argv, &[2]).is_none(),
            "载荷被截断时 `ls` 可能只是 `lsblk` 的前缀，不能算证据"
        );
    }

    /// 规则 S 只是"这段文字**出现在**载荷里"。它必须老实说自己弱：
    /// `ls` 在 `lsblk` 载荷里"出现"过，但它是不是真跑的那条命令，规则 S 不知道。
    #[test]
    fn rule_substring_is_never_labelled_exact() {
        let argv = argv_of(&["bash", "-c", "lsblk"]);
        let hit = match_rule("ls", false, &argv, &[]).expect("子串命中");
        assert_eq!(hit, RuleHit::Substring);
        assert_ne!(hit.text(), "argv exact");
        assert_ne!(hit.text(), "argv overlap 100%");
        assert_ne!(hit.text(), "argv prefix 100%");
    }

    // ---------------- 规则 G（复合命令分段） ----------------

    /// V03_PROMPT 里的真实复合命令：整串与 curl 的 argv 只有 62.5% 重叠，
    /// 但按 `;` 切开之后第一段是 100%。
    #[test]
    fn rule_segment_rescues_the_real_compound_command() {
        let cmd = "curl -s -m 3 http://127.0.0.1:9/ ; echo \"exit=$?\"";
        let argv = argv_of(&["curl", "-s", "-m", "3", "http://127.0.0.1:9/"]);
        // 整串判定（规则 T）确实不够：8 个 token 里只对上 5 个。
        let (toks, _) = shlex_split(cmd);
        assert_eq!(token_overlap(&toks, false, &argv).expect("前提成立"), (62, false));
        let hit = match_rule(cmd, false, &argv, &[]).expect("must match");
        assert_eq!(hit, RuleHit::Segment);
        assert_eq!(hit.text(), "argv segment");
    }

    #[test]
    fn segment_split_respects_quotes() {
        // 引号里的 `;` `|` `&&` 都不算分隔符。
        let s = split_segments("echo \"a;b|c&&d\" ; ls 'x;y'");
        assert_eq!(s.len(), 2, "只在引号外切：{:?}", s);
        assert!(s[0].contains("a;b|c&&d"));
        assert_eq!(s[1].trim(), "ls 'x;y'");
        // 反斜杠转义的分隔符同理。
        assert_eq!(split_segments("echo a\\;b").len(), 1);
        // 全是操作符的输入不许 panic，也不许造出空匹配。
        assert_eq!(split_segments(";;&&||").len(), 5);
        assert_eq!(split_segments("").len(), 1);
    }

    #[test]
    fn split_commands_keeps_pipes_but_splits_semicolons() {
        let segs = split_commands("curl http://x/y.sh | sh; echo done");
        assert_eq!(segs.len(), 2);
        assert!(segs[0].contains("|"), "pipe must survive: {:?}", segs[0]);
        let segs = split_commands("echo \"a;b\" && echo 'x|y'\nls");
        assert_eq!(segs.len(), 3, "quotes protect separators: {:?}", segs);
    }

    #[test]
    fn split_commands_false_positive_20261011() {
        // 2026-10-11 真实误报：三条不相干的子命令被整串匹配拼中。
        // "curl" 在中文 echo 里，`|` 在 `| grep` 里，"sh" 在单词 "dsh" 里。
        let cmd = "echo \"resolve:\"; getent hosts h.ts.net 2>/dev/null || echo \"(DNS \u{672c}\u{673a} curl test)\"\nss -ltnp 2>/dev/null | grep -E ':3080'\nINNER='exec dsh web --host 0.0.0.0'";
        let segs = split_commands(cmd);
        // "curl" 和 "|"/"sh" 必须落在不同的子命令里
        let has_curl = segs.iter().filter(|s| s.contains("curl ")).count();
        let has_pipe_sh = segs.iter().filter(|s| s.contains("|") && s.contains("sh")).count();
        assert_eq!(has_curl, 1);
        // 没有任何一条子命令同时包含三者
        for seg in &segs {
            let all = seg.contains("curl ") && seg.contains(" | ") && seg.contains("sh");
            assert!(!all, "false positive segment: {:?}", seg);
        }
        let _ = has_pipe_sh;
    }

    #[test]
    fn segment_splits_on_every_operator() {
        for cmd in ["a ; b", "a && b", "a || b", "a | b"] {
            assert_eq!(split_segments(cmd).len(), 2, "{} 必须被切开", cmd);
        }
        // 单个 `&`（后台）不在切割集里。
        assert_eq!(split_segments("a & b").len(), 1);
    }

    /// 复合命令的后半段也可能是真正跑起来的那条（`rm -rf x && ls`）。
    #[test]
    fn segment_matches_any_position() {
        let hit = match_rule("true && ls -la /tmp", false, &argv_of(&["ls", "-la", "/tmp"]), &[]).expect("must match");
        assert_eq!(hit, RuleHit::Segment);
    }

    /// 单段命令不许走规则 G —— 否则 `argv overlap 100%` 会被同一件事降级成
    /// `argv segment`（标签变弱就是失真）。
    #[test]
    fn segment_rule_requires_two_segments() {
        let hit = match_rule("echo hello", false, &argv_of(&["/bin/echo", "hello"]), &[]).expect("must match");
        assert_eq!(
            hit,
            RuleHit::Tokens {
                pct: 100,
                truncated: false
            }
        );
    }

    /// 截断点落在最后一段里 → 那一段不完整，不拿它当证据；它前面的段仍然可用。
    #[test]
    fn segment_rule_skips_only_the_truncated_tail() {
        let argv = argv_of(&["ls", "-la", "/tmp"]);
        // 第二段被 `bash_cmd_max` 切断了，但第一段完好。
        let hit = match_rule("ls -la /tmp && echo de", true, &argv, &[]).expect("前一段可用");
        assert_eq!(hit, RuleHit::Segment);
        // 只有被切断的那一段能对上时，宁可整条不认。
        assert!(match_rule("echo de && ls -la /tm", true, &argv, &[]).is_none());
    }

    /// 规则 G 仍然受 basename 前提约束：不同名字的命令不许靠分段凑上。
    #[test]
    fn segment_rule_keeps_the_basename_premise() {
        let cmd = "curl -s http://x/ ; echo done";
        assert!(match_rule(cmd, false, &argv_of(&["wget", "-s", "http://x/"]), &[]).is_none());
    }

    /// 优先级：同一条 exec 同时满足 S 和 G 时取 S（更强）。
    #[test]
    fn rule_priority_is_exact_then_substring_then_segment_then_overlap() {
        let cmd = "make -j4";
        // 不带引号地出现在载荷里 → 规则 D 就够（D 比 S 强，必须先赢）。
        assert_eq!(
            match_rule(cmd, false, &argv_of(&["bash", "-c", "cd /x && make -j4"]), &[]).expect("D"),
            RuleHit::Direct
        );
        // 反过来说：`argv overlap` 只在 S/G 都不适用时才轮得到。
        assert_eq!(
            match_rule("make -j4", false, &argv_of(&["make", "-j4"]), &[]).expect("T"),
            RuleHit::Direct
        );
        // S 胜过 G：载荷把整条复合命令引起来放进 `eval`，cmd 本身也被切成两段。
        let argv = argv_of(&["bash", "-c", "cd /x && eval 'make -j4 ; echo done'"]);
        assert_eq!(
            match_rule("make -j4 ; echo done", false, &argv, &[]).expect("S"),
            RuleHit::Substring
        );
    }

    /// 同一条 exec 分给两条调用：更长的 cmd 先赢（规则不变，只是换了规则名）。
    #[test]
    fn binder_labels_segment_hits_end_to_end() {
        let mut b = ExactBinder::new(true);
        let cmd = "curl -s -m 3 http://127.0.0.1:9/ ; echo \"exit=$?\"";
        let _ = run(
            &mut b,
            vec![
                call(S, "toolu_rc1", cmd, false),
                exec(
                    S + 1,
                    777,
                    "/usr/bin/curl",
                    &["curl", "-s", "-m", "3", "http://127.0.0.1:9/"],
                ),
            ],
        );
        let bs = b.stats;
        assert_eq!(bs.calls_matched, 1);
        assert_eq!(bs.by_segment, 1);
        assert_eq!(bs.by_direct, 0);
    }

    /// 规则 S 的端到端版本：`sh -c '<cmd>'` 这种短载荷下，cmd 整串就是载荷的一部分。
    /// 与规则 G 的那条测试配对 —— 一个证明"短载荷走 S"，一个证明"长载荷（真实
    /// Claude Code 的 snapshot 前奏）只能走 G"。
    #[test]
    fn binder_labels_substring_hits_end_to_end() {
        let mut b = ExactBinder::new(true);
        let cmd = "make -j4";
        // `eval '<cmd>'`：整串确实在载荷里，但前面是引号不是 token 边界，
        // 所以规则 D 拒绝、规则 S 接手。
        let payload = format!("cd /work && set -o pipefail; eval '{}'", cmd);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_s", cmd, false),
                exec(S + 1, 778, "/bin/bash", &["/bin/sh", "-c", &payload]),
            ],
        );
        let bs = b.stats;
        assert_eq!(bs.calls_matched, 1);
        assert_eq!(bs.by_substring, 1);
        assert_eq!(bs.by_segment, 0);
        // 行里的规则标签必须是 S 的原文，绝不能写成 exact。
        let text = format!("{:?}", binds(&out)[0].payload);
        assert!(text.contains("argv substring"), "{text}");
        assert!(!text.contains("argv exact"), "{text}");
    }

    // ---------------- 时间窗 / 认领顺序 ----------------

    #[test]
    fn exec_before_the_call_never_matches() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                exec(S, 100, "/bin/echo", &["echo", "hi"]),
                call(2 * S, "t1", "/bin/echo hi", false),
            ],
        );
        assert!(binds(&out).is_empty());
        assert_eq!(b.stats.calls_matched, 0);
        // exec 行没被标 exact。
        assert_eq!(out[0].binding, Binding::None);
    }

    #[test]
    fn window_is_bounded_at_120s() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(0, "t1", "/bin/echo hi", false),
                exec(EXEC_AFTER_CALL_NS, 100, "/bin/echo", &["/bin/echo", "hi"]),
            ],
        );
        assert_eq!(binds(&out).len(), 1, "120s 整点仍在窗内");

        let mut b2 = ExactBinder::new(true);
        let out2 = run(
            &mut b2,
            vec![
                call(0, "t1", "/bin/echo hi", false),
                exec(EXEC_AFTER_CALL_NS + 1, 100, "/bin/echo", &["/bin/echo", "hi"]),
            ],
        );
        assert!(binds(&out2).is_empty(), "超出 1ns 就不认");
    }

    #[test]
    fn retries_pair_off_in_order_without_cross_wiring() {
        // 验收 #2：同一条命令两次，两条 exec —— 第一条 exec 对第一条调用。
        let mut b = ExactBinder::new(true);
        let cmd = "/bin/echo hello-v03-bind";
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", cmd, false),
                call(2 * S, "toolu_b", cmd, false),
                exec(3 * S, 500, "/bin/echo", &["/bin/echo", "hello-v03-bind"]),
                exec(4 * S, 501, "/bin/echo", &["/bin/echo", "hello-v03-bind"]),
            ],
        );
        let bs = binds(&out);
        assert_eq!(bs.len(), 2);
        assert_eq!(bs[0].corr.tool_use_id.as_deref(), Some("toolu_a"));
        assert_eq!(bs[1].corr.tool_use_id.as_deref(), Some("toolu_b"));
        // 两条 exec 各自被标 exact，并且**没有**交叉：500 ↔ a、501 ↔ b。
        let e0 = out
            .iter()
            .find(|e| e.pid == Some(500) && e.kind == Kind::RuntimeProcExec)
            .unwrap();
        let e1 = out
            .iter()
            .find(|e| e.pid == Some(501) && e.kind == Kind::RuntimeProcExec)
            .unwrap();
        assert_eq!(e0.corr.tool_use_id.as_deref(), Some("toolu_a"));
        assert_eq!(e1.corr.tool_use_id.as_deref(), Some("toolu_b"));
        assert_eq!(b.stats.calls_matched, 2);
    }

    #[test]
    fn a_single_exec_claims_exactly_one_call() {
        let mut b = ExactBinder::new(true);
        let cmd = "/bin/echo hi";
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", cmd, false),
                call(2 * S, "toolu_b", cmd, false),
                exec(3 * S, 500, "/bin/echo", &["/bin/echo", "hi"]),
            ],
        );
        assert_eq!(binds(&out).len(), 1);
        assert_eq!(b.stats.calls_matched, 1);
        assert_eq!(binds(&out)[0].corr.tool_use_id.as_deref(), Some("toolu_a"), "最早者胜");
    }

    #[test]
    fn longest_command_wins_over_a_stale_short_one() {
        // `ls` 是陈旧的未认领调用，`ls -la` 才是这条 exec 的真身。
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_old", "ls", false),
                call(2 * S, "toolu_new", "ls -la /tmp", false),
                exec(3 * S, 700, "/bin/ls", &["/bin/ls", "-la", "/tmp"]),
            ],
        );
        let bs = binds(&out);
        assert_eq!(bs.len(), 1);
        assert_eq!(bs[0].corr.tool_use_id.as_deref(), Some("toolu_new"));
    }

    #[test]
    fn an_exec_already_inside_a_bound_subtree_does_not_claim_a_second_call() {
        let mut b = ExactBinder::new(true);
        let cmd = "/bin/sh -c build";
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", cmd, false),
                exec(2 * S, 900, "/bin/sh", &["/bin/sh", "-c", "build"]),
                // 同一次调用里 sh 又 exec 了子命令：它已经在子树里，不该再吃一条 call。
                call(3 * S, "toolu_b", "make all", false),
                exec(4 * S, 900, "/usr/bin/make", &["make", "all"]),
            ],
        );
        // 第二条 call 没被认领（exec 的 pid 已经是 exact）。
        assert_eq!(b.stats.calls_matched, 1);
        assert_eq!(binds(&out).len(), 1);
    }

    // ---------------- 子树 ----------------

    #[test]
    fn subtree_inherits_binding_and_the_fork_row_is_marked_too() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "/bin/echo hello-v03-bind", false),
                fork(2 * S, 10, 11), // 父进程 fork 出被匹配的那个
                exec(2 * S + 1, 11, "/bin/echo", &["/bin/echo", "hello-v03-bind"]),
                fork(3 * S, 11, 12), // 它自己再 fork 一个（孙子）
                exec(3 * S + 1, 12, "/usr/bin/tee", &["tee", "-a", "log"]),
            ],
        );
        let by_pid = |p: u32| {
            out.iter()
                .find(|e| e.pid == Some(p) && e.kind != Kind::DerivedBind)
                .cloned()
        };
        // 被匹配的 exec 进程。
        assert_eq!(by_pid(11).unwrap().binding, Binding::Exact);
        // 孙子的 exec 也继承了绑定（整棵子树）。
        assert_eq!(by_pid(12).unwrap().binding, Binding::Exact);
        // 创建了它的那条 fork 行（pid=10，本身没被绑定）也要标出来。
        let fork_row = out
            .iter()
            .find(|e| e.kind == Kind::RuntimeProcFork && e.pid == Some(10))
            .unwrap();
        assert_eq!(fork_row.binding, Binding::Exact);
        assert_eq!(fork_row.corr.tool_use_id.as_deref(), Some("toolu_a"));
        // 孙子 fork 行（父=11，已绑定）也标。
        let fork2 = out
            .iter()
            .find(|e| e.kind == Kind::RuntimeProcFork && e.pid == Some(11))
            .unwrap();
        assert_eq!(fork2.binding, Binding::Exact);
    }

    #[test]
    fn unrelated_processes_stay_unbound() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "/bin/echo hello-v03-bind", false),
                exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hello-v03-bind"]),
                exec(2 * S + 5, 42, "/usr/bin/unrelated", &["unrelated", "--x"]),
            ],
        );
        let other = out.iter().find(|e| e.pid == Some(42)).unwrap();
        assert_eq!(
            other.binding,
            Binding::None,
            "无关进程必须保持 none（而不是被顺手标上 exact）"
        );
        assert!(other.corr.tool_use_id.is_none());
    }

    #[test]
    fn unbound_tool_calls_keep_their_question_mark() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "curl -s -m 3 http://127.0.0.1:9/", false),
                exec(2 * S, 11, "/usr/bin/python3", &["python3", "train.py"]),
            ],
        );
        let c = out.iter().find(|e| e.kind == Kind::AgentToolCall).unwrap();
        assert_eq!(
            c.binding,
            Binding::Heuristic,
            "没匹配上的 tool.call 保持会话级等级 → 仍打 `?`"
        );
        assert!(binds(&out).is_empty());
        assert_eq!(b.stats.calls_seen, 1);
        assert_eq!(b.stats.calls_matched, 0);
    }

    #[test]
    fn later_agent_rows_of_a_matched_call_upgrade_to_exact() {
        // tool.result 通常晚于 exec 到达（live 模式），它属于同一次调用 → 升级。
        let mut b = ExactBinder::new(true);
        let mut res = call(3 * S, "toolu_a", "/bin/echo hi", false);
        res.kind = Kind::AgentToolResult;
        res.payload = Payload::ToolResult {
            tool: Some("Bash".into()),
            status: "success".into(),
            result_preview: "hi".into(),
        };
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "/bin/echo hi", false),
                exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"]),
                res,
            ],
        );
        let r = out.iter().find(|e| e.kind == Kind::AgentToolResult).unwrap();
        assert_eq!(r.binding, Binding::Exact);
    }

    // ---------------- 派生行 ----------------

    #[test]
    fn one_derived_row_per_match_with_the_real_rule_named() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "curl -s -m 3 http://127.0.0.1:9/", false),
                exec(
                    2 * S,
                    11,
                    "/bin/bash",
                    &["bash", "-c", "curl -s -m 3 http://127.0.0.1:9/"],
                ),
            ],
        );
        let bs = binds(&out);
        assert_eq!(bs.len(), 1, "一次匹配只产出一行");
        assert_eq!(bs[0].layer, Layer::Derived);
        assert_eq!(bs[0].ts_ns, 2 * S, "派生行落在它解释的那条 exec 的时间位置上");
        match &bs[0].payload {
            Payload::Bind {
                tool,
                cmd_preview,
                exec_filename,
                rule,
                delta_ms,
                pid,
                subtree_pids,
            } => {
                assert_eq!(tool, "Bash");
                assert_eq!(cmd_preview, "curl -s -m 3 http://127.0.0.1:9/");
                assert_eq!(exec_filename, "/bin/bash");
                assert_eq!(rule, "argv exact");
                assert_eq!(*delta_ms, 1000);
                assert_eq!(*pid, 11);
                assert_eq!(*subtree_pids, 1);
            }
            other => panic!("expected Bind payload, got {:?}", other),
        }
        assert_eq!(bs[0].corr.tool_use_id.as_deref(), Some("toolu_a"));
        assert_eq!(bs[0].corr.session_id.as_deref(), Some("sess0001"));
        assert_eq!(b.stats.derived_rows, 1);
    }

    #[test]
    fn derived_row_takes_its_slot_right_after_the_exec() {
        let mut b = ExactBinder::new(true);
        let out = run(
            &mut b,
            vec![
                call(S, "toolu_a", "/bin/echo hi", false),
                exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"]),
                exec(3 * S, 12, "/bin/true", &["true"]),
            ],
        );
        let kinds: Vec<Kind> = out.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::AgentToolCall,
                Kind::RuntimeProcExec,
                Kind::DerivedBind,
                Kind::RuntimeProcExec,
            ]
        );
    }

    #[test]
    fn disabled_binder_changes_nothing() {
        let mut b = ExactBinder::new(false);
        let evs = vec![
            call(S, "toolu_a", "/bin/echo hi", false),
            exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"]),
        ];
        let n = evs.len();
        let out = run(&mut b, evs);
        assert_eq!(out.len(), n);
        assert!(binds(&out).is_empty());
        assert!(out.iter().all(|e| e.binding != Binding::Exact));
        assert_eq!(b.stats.calls_seen, 0, "--no-bind 下连账都不记");
    }

    #[test]
    fn non_shell_tools_are_ignored() {
        let mut b = ExactBinder::new(true);
        let mut ev = call(S, "toolu_a", "/bin/echo hi", false);
        ev.payload = Payload::ToolCall {
            tool: "Read".into(),
            input_preview: "{\"file_path\":\"/bin/echo\"}".into(),
            input_bytes: 25,
            via_mcp: false,
            bash_cmd: None,
        };
        let out = run(&mut b, vec![ev, exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"])]);
        assert!(binds(&out).is_empty());
        assert_eq!(b.stats.calls_seen, 0);
    }

    #[test]
    fn exec_without_argv_is_never_guessed_at() {
        let mut b = ExactBinder::new(true);
        let mut e = exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"]);
        e.payload = Payload::ProcExec {
            filename: "/bin/echo".into(),
            argv: Vec::new(),
            argc_total: None,
        };
        let out = run(&mut b, vec![call(S, "toolu_a", "/bin/echo hi", false), e]);
        assert!(binds(&out).is_empty(), "没有 argv 就没有 join key，不许猜");
        assert_eq!(
            out.iter().find(|x| x.kind == Kind::RuntimeProcExec).unwrap().binding,
            Binding::None
        );
    }

    #[test]
    fn unresolved_fork_defers_its_whole_batch_suffix() {
        // 暂缓一行、放行它**后面**的行 = 时间序倒挂（先印 exec、后印 fork）。
        // 实测缺陷，见 BUILD_LOG §15.4：所以暂缓的是从这条 fork 起的整段后缀。
        let mut b = ExactBinder::new(true);
        let c = run(
            &mut b,
            vec![fork(2 * S, 10, 11), exec(2 * S + 1, 42, "/usr/bin/other", &["other"])],
        );
        assert!(c.is_empty(), "第一条未定论的 fork 之后的行必须一起等，不能抢跑");
        let tail = b.finish();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].kind, Kind::RuntimeProcFork);
        assert_eq!(tail[1].pid, Some(42), "放行后仍是 fork 在前");
    }

    #[test]
    fn held_suffix_keeps_the_derived_row_and_the_order() {
        // 一段后缀里完全可能有产生 bind 行的 exec 行 —— 派生行必须跟着一起暂缓，
        // 否则它会被静默丢掉（那才是真正不可接受的错：少了一行证据）。
        let mut b = ExactBinder::new(true);
        let _ = run(&mut b, vec![call(S, "toolu_a", "/bin/echo hi", false)]);
        let c = run(&mut b, vec![fork(2 * S, 10, 11)]);
        assert!(c.is_empty(), "子进程还没 exec，fork 行先不下结论");
        let d = run(&mut b, vec![exec(2 * S + 1, 11, "/bin/echo", &["/bin/echo", "hi"])]);
        let kinds: Vec<Kind> = d.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![Kind::RuntimeProcFork, Kind::RuntimeProcExec, Kind::DerivedBind],
            "fork（放行）+ exec + bind，一行都不能少、顺序不能乱"
        );
        assert_eq!(d[0].binding, Binding::Exact, "放行时 fork 行已经拿到子进程的判定");
    }

    #[test]
    fn pieces_split_across_batches_still_bind() {
        // merger 会把一次 fork+exec 放进同一批，但 exec 有可能落到下一批
        // （例如它发生在重排窗口之后）。分批调用不能丢状态。
        let mut b = ExactBinder::new(true);
        let a = run(&mut b, vec![call(S, "toolu_a", "/bin/echo hi", false)]);
        assert!(binds(&a).is_empty());
        let c = run(&mut b, vec![exec(2 * S, 11, "/bin/echo", &["/bin/echo", "hi"])]);
        assert_eq!(binds(&c).len(), 1);
    }

    #[test]
    fn a_held_tool_call_is_never_claimed_twice() {
        // 暂缓的后缀在下一批会被 pass 1 重新看到。如果那条 tool.call 被**再入队一次**，
        // 它就多出一份"未认领"的副本 —— 于是同一个命令的第二次 exec 会认领副本，
        // 把一个无关的 pid 标成 `exact`（本工具最不该犯的错：凭空说一句确定的话）。
        let mut b = ExactBinder::new(true);
        let a = run(
            &mut b,
            vec![fork(2 * S, 10, 11), call(2 * S + 1, "toolu_a", "/bin/echo hi", false)],
        );
        assert!(a.is_empty(), "fork 未定论：从它起的整段后缀一起等");
        let c = run(&mut b, vec![exec(2 * S + 2, 11, "/bin/echo", &["/bin/echo", "hi"])]);
        assert_eq!(binds(&c).len(), 1);
        assert_eq!(b.stats().calls_seen, 1, "暂缓的 tool.call 被重复计数");
        // 一条 tool.call 只对应一条 exec：一模一样的第二条 exec 不该再被认领。
        let d = run(&mut b, vec![exec(2 * S + 3, 12, "/bin/echo", &["/bin/echo", "hi"])]);
        assert!(binds(&d).is_empty(), "重放暂缓前缀让同一条调用认领了两次");
        assert_eq!(b.stats().calls_matched, 1);
        assert_eq!(b.stats().execs_seen, 2, "暂缓的 exec 被重复计数");
    }

    #[test]
    fn pathological_call_flood_is_bounded() {
        // 几千条 tool.call 而内核一条 exec 都没有：内部表不能无限涨。
        let mut b = ExactBinder::new(true);
        for i in 0..(MAX_PENDING_CALLS + 10) {
            let _ = run(&mut b, vec![call(S + i as u64, "t", "/bin/echo hi", false)]);
        }
        assert!(b.calls.len() <= MAX_PENDING_CALLS);
    }
}
