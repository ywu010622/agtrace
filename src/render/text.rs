//! strace 风格文本时间线（DESIGN.md §4.2）。
//!
//! 列定义：
//! ```text
//! {rel_ts:>13.6}  {layer:<8} {key:<9} {kind:<15} {payload}
//! ```

use super::{
    BOLD, DIM, MAX_COLS, RED, RESET, RenderOpts, YELLOW, cap_lines, colorize, display_width, fit_fail, layer_str,
    markers, payload_line, time_origin, trunc_detail, truncate_display,
};
use crate::event::{Binding, Event, Kind, Layer, corr_key};
use std::io::Write;

/// v0.6 失败段里注解行（血缘 / 对账 / 嗅探）的缩进。
///
/// 用 `  ` 而不是对齐到正文列：真正对齐需要把 `fit_fail` 的列预算也算进来，
/// 而这几行是**注解**，视觉上"缩进去一档"就够了。`└─` 自己已经说明了从属关系。
const INDENT: &str = "        ";

/// 启动横幅的内容（§4.2 第一行）。
pub struct Header {
    /// 例如 `pid 644607 (tree)` / `cgroup /sys/fs/cgroup/x` / `session 65a34ef2`
    pub target: String,
    pub session: Option<String>,
    pub binding: Option<Binding>,
    pub sources: Vec<String>,
    pub following: bool,
    /// 额外附注（例如 openshell 的 time-base 说明）。
    pub notes: Vec<String>,
}

pub struct TextRenderer {
    opts: RenderOpts,
    origin: Option<u64>,
    /// 已经敲定过原始时间 —— 之后新到的事件不会把 origin 往前挪，
    /// 否则先输出的行的相对时间会莫名其妙地变大。
    origin_locked: bool,
    header_done: bool,
}

impl TextRenderer {
    pub fn new(opts: RenderOpts) -> Self {
        TextRenderer {
            opts,
            origin: None,
            origin_locked: false,
            header_done: false,
        }
    }

    /// v0.4 §13.4：把相对时间的原点**钉死**在会话起点上。
    ///
    /// `--failures-only` 下时间线的开头被剪掉了（成功的事件一条不剩），渲染器如果
    /// 照老规矩按"第一条打印出来的事件"定原点，那条 `4.995s` 的失败会变成
    /// `0.000s` —— 而用户拿这个数去和别的日志对表时，对的是错的那一秒。
    /// 失败归因器一路看着**完整**的事件流，只有它知道会话真正从哪一刻开始。
    ///
    /// 首次调用生效（与 `render_batch` 的 `origin_locked` 同一把锁），
    /// 传 0 视为"我还不知道"。
    pub fn lock_origin(&mut self, wall_ns: u64) {
        if wall_ns == 0 || self.origin_locked {
            return;
        }
        self.origin = Some(wall_ns);
        self.origin_locked = true;
    }

    pub fn header(&mut self, h: &Header) -> String {
        let mut s = String::new();
        let mut binding_caveat = false;
        s.push_str("agtrace: target=");
        s.push_str(&h.target);
        if let Some(sess) = &h.session {
            s.push_str(&format!(", session={}", sess));
            if let Some(b) = h.binding {
                s.push_str(&format!(" (binding: {})", b.as_str()));
                // §3.5：绑不上就说绑不上，不留想象空间。
                //
                // 这句警示单独占一行，而不是接在目标描述后面：接在后面会把这行推到
                // 120 列以上，而按 §3 被截掉的恰好是它 —— 保真的话不能是"说半句"。
                if b != Binding::Exact {
                    binding_caveat = true;
                }
            }
        }
        s.push_str(&format!(", {} sources", h.sources.len()));
        s.push_str(if h.following { ", following" } else { ", read to EOF" });
        for n in &h.notes {
            // 注记一律先 one_line 再限宽：一条注记必须只占一行，超宽也不能在词中间断掉。
            // 前缀算进宽度里 —— 只限正文会让最终一行仍然越界，再被 cap_lines 补一刀。
            let line = crate::render::cap_note(&format!("agtrace: {}", crate::event::one_line(n)));
            s.push('\n');
            s.push_str(&line);
        }
        if binding_caveat {
            s.push_str(
                "\nagtrace: binding not exact: agent events link to the process tree by time \
                 proximity only, not causation (§3.5)",
            );
        }
        self.header_done = true;
        // 横幅与注记同属时间线的一部分，一样受 120 列约束（§3）。
        cap_lines(&s)
    }

    /// 渲染一批事件。返回应当写出的文本（含换行）。
    pub fn render_batch(&mut self, events: &[Event]) -> String {
        if !self.origin_locked
            && let Some(o) = time_origin(events)
        {
            self.origin = Some(o);
            // 只有拿到过事件之后才锁定；之后即使出现更早的 (late) 事件也不回退。
            self.origin_locked = true;
        }
        let mut out = String::new();
        for ev in events {
            out.push_str(&self.render_one(ev));
            out.push('\n');
        }
        out
    }

    pub fn render_one(&self, ev: &Event) -> String {
        let rel = match (ev.ts_wall_ns, self.origin) {
            (w, Some(o)) if w >= o => (w - o) as f64 / 1e9,
            (w, None) if w > 0 => {
                // 还没定 origin（第一条就没有 wall 时间的情况）—— 用 0 起点。
                let _ = w;
                0.0
            }
            _ => 0.0,
        };

        let layer = layer_str(ev);
        let layer_col = if ev.layer == Layer::Derived {
            colorize(&self.opts, BOLD, &layer)
        } else {
            colorize(&self.opts, ev.layer.color(), &layer)
        };
        let key = format!("{:<9}", corr_key(ev.layer, &ev.corr, ev.pid));
        let kind = format!("{:<15}", ev.kind.short());

        // §3：默认一行不超过 MAX_COLS 列（按**显示列**算，CJK 记 2）。
        //
        // 预算 = 120 − 前缀列 − 标记列。前缀是定宽的（见文件头的列定义；
        // layer/key/kind 已经 padding，display_width 拿到的就是它们实际占的列），
        // 标记列必须先算出来才能知道正文还剩多少。
        //
        // 预算必须在**构造正文之前**算出来：v0.3 的 bind 行要用它做定向省略
        // （见 render::bind_line）。其它 payload 忽略这个参数。
        let mut mk = markers(ev);
        let prefix_cols = 13 + 2 + display_width(&layer) + 1 + display_width(&key) + 1 + display_width(&kind) + 1;
        let budget = MAX_COLS.saturating_sub(prefix_cols).saturating_sub(display_width(&mk));
        let mut body = payload_line(ev, budget);

        // 最后一处转义闸门：正文里承载的是**不可信文本**（内核给的路径/argv、
        // transcript 给的工具名与状态串），而一个裸 `\x1b` 就是一个终端注入
        // 原语（改窗口标题、清屏、在别人的 TTY 上画东西）。上游大部分字段已经
        // 过 `one_line`，但"大部分"不是保证，所以在这里再兜一次 —— 出口只有
        // 一个，闸门就放在出口。
        //
        // 必须在 `colorize` **之前**：agtrace 自己的 ANSI 是之后才包上去的，
        // 先着色再转义会把自家的颜色码一起打成可见文本。
        // 位置也必须在宽度判定之前：转义后的 `\x1b` 是 4 列，按原样量会低估宽度。
        body = crate::event::one_line(&body);

        // 截断在**着色之前**做：ANSI 转义也是字节，先着色再量长度会把转义码
        // 算成可见宽度，于是明明只有 100 列的行被误判成超宽。
        let mut display_capped = false;
        if display_width(&body) > budget {
            // 预留 1 列给行尾的 `~`：内容被砍过就必须看得见（§4.3 没有静默丢失）。
            let (cut, _) = truncate_display(&body, budget.saturating_sub(1));
            body = format!("{}~", cut);
            // `~` 已经在正文尾部了，标记列里不再重复一个。
            mk = mk.replace(" ~", "");
            display_capped = true;
        }

        // §8 ⑤：watchlist 命中 → 整行标红（alert-only，只呈现不处置）。
        // v0.4.1：failure attribution 行（derived.fail / XX）同样标红 —— 用户明确要求 error 为红色。
        if ev.watch || ev.kind == Kind::DerivedFail {
            body = colorize(&self.opts, RED, &body);
        } else if ev.retry {
            body = colorize(&self.opts, YELLOW, &body);
        }

        let mk_col = if mk.is_empty() {
            String::new()
        } else if ev.watch || ev.kind == Kind::DerivedFail {
            colorize(&self.opts, RED, &mk)
        } else {
            colorize(&self.opts, DIM, &mk)
        };

        let mut line = format!("{:>13.6}  {} {} {} {}{}", rel, layer_col, key, kind, body, mk_col);

        // §4.3：截断必须可发现 —— `-v` / `--full` 下展开细节。
        //
        // 续行同样受 MAX_COLS 约束：`-v` 是给人看的，一行折成两行反而更难读。
        // 关键信息（字段名、字节数）在行首，被砍掉的是尾部的说明文字。
        if self.opts.verbose || self.opts.full {
            line.push('\n');
            line.push_str(&colorize(
                &self.opts,
                DIM,
                &Self::cap_line(&format!(
                    "{:>13}  ts_src={}{}",
                    "",
                    ev.ts_src.as_str(),
                    if let Some(id) = ev.corr.tool_use_id.as_deref() {
                        // 这一串直接来自 transcript，和正文同样不可信 —— 续行也是
                        // 终端输出，闸门不能只设在正文那一条上。
                        format!("  tool_use_id={}", crate::event::one_line(id))
                    } else {
                        String::new()
                    }
                )),
            ));
            // 显示层截断（不是字段截断）也要能查到 —— 这一行没进 trunc，
            // 因为字段本身是完整的，被砍掉的只是**这一行的显示**。
            if display_capped {
                line.push('\n');
                line.push_str(&colorize(
                    &self.opts,
                    DIM,
                    &Self::cap_line(&format!(
                        "{:>13}  display-capped at {} cols; --output json keeps the full field",
                        "", MAX_COLS
                    )),
                ));
            }
            if let Some(d) = trunc_detail(ev) {
                line.push('\n');
                line.push_str(&colorize(
                    &self.opts,
                    DIM,
                    &Self::cap_line(&format!("{:>13}  {}", "", d)),
                ));
            }
            // notes 与 trunc 分开显示：一个是"被截掉了"，一个是"关于这行的说明"。
            for n in &ev.notes {
                line.push('\n');
                line.push_str(&colorize(
                    &self.opts,
                    DIM,
                    &Self::cap_line(&format!("{:>13}  note: {}", "", n)),
                ));
            }
            if ev.late {
                line.push('\n');
                line.push_str(&colorize(
                    &self.opts,
                    DIM,
                    &Self::cap_line(&format!(
                        "{:>13}  (late): this agent event was written to disk after the timeline \
                         had already moved past this position, so the row order is not the real order",
                        ""
                    )),
                ));
            }
        }
        line
    }

    /// `&mut self`：渲染要推进 origin 状态，而 origin 一旦锁定就不能回退
    /// （否则先输出的行相对时间会变大）。所以借用可变引用，而不是拷贝一份
    /// renderer —— 拷贝会让 origin 的推进在拷贝上蒸发，下次调用又从未锁定开始。
    pub fn write_batch<W: Write>(&mut self, w: &mut W, events: &[Event]) -> std::io::Result<()> {
        let s = self.render_batch(events);
        w.write_all(s.as_bytes())
    }

    /// §3：任何一行都不超过 MAX_COLS 列。续行承载细节，被砍时同样以 `~` 收尾。
    fn cap_line(s: &str) -> String {
        if display_width(s) <= MAX_COLS {
            return s.to_string();
        }
        let (cut, _) = truncate_display(s, MAX_COLS - 1);
        format!("{}~", cut)
    }

    /// 收尾统计行。所有计数都来自实际发生的事，不估算。
    pub fn summary(&self, ev: &Summary) -> String {
        let mut s = String::new();
        let c = |x: &str| colorize(&self.opts, DIM, x);
        s.push_str(&format!(
            "{}\n",
            c(&format!(
                "--- {} events: agent {} / runtime {} / infra {} / policy {} / derived {}",
                ev.total, ev.agent, ev.runtime, ev.infra, ev.policy, ev.derived
            ))
        ));
        // 绝对时间跨度：相对时间戳没有"这是几点"的信息，而排查时经常要拿这个
        // 去跟别的日志对表。两端都给 ISO8601（与 transcript 原生格式一致）。
        if let (Some(a), Some(b)) = (ev.first_wall, ev.last_wall)
            && b > a
        {
            s.push_str(&format!(
                "{}\n",
                c(&format!(
                    "--- span {} -> {} ({:.6}s)",
                    crate::adapter::iso8601_ms(a),
                    crate::adapter::iso8601_ms(b),
                    (b - a) as f64 / 1e9
                ))
            ));
        }
        s.push_str(&self.failures_section(ev));
        let mut flags = Vec::new();
        if ev.from_agent > 0 && ev.from_kernel > 0 {
            flags.push(format!(
                "timestamp source: kernel {} / wallclock-converted {} (converted rows sort by the sampled offset)",
                ev.from_kernel, ev.from_agent
            ));
        }
        if ev.late > 0 {
            flags.push(format!(
                "{} (late) row(s) (agent event landed after its timeline position)",
                ev.late
            ));
        }
        if ev.truncated > 0 {
            flags.push(format!("{} truncated row(s) (`-v` expands)", ev.truncated));
        }
        if ev.lost > 1 {
            flags.push(format!("{} loss report(s)", ev.lost));
        }
        if ev.collapse_rows > 0 {
            flags.push(format!(
                "{} collapsed row(s) summarize {} raw line(s) (`-v` restores them; `--output json` never collapses)",
                ev.collapse_rows, ev.collapse_raw
            ));
        }
        if !flags.is_empty() {
            s.push_str(&format!("{}\n", c(&format!("--- {}", flags.join("; ")))));
        }
        if ev.binding != Some(Binding::Exact) && ev.session.is_some() {
            s.push_str(&format!(
                "{}\n",
                colorize(
                    &self.opts,
                    YELLOW,
                    "--- pid_binding is not exact: agent events are linked to the process tree only by time proximity (§3.5)"
                )
            ));
        }
        cap_lines(&s)
    }

    /// v0.4 §13.4：收尾的失败段。位置在事件计数之后、flags 之前 —— 先回答
    /// "这一轮一共多少行"，再回答"其中失败的有几次、各自失败在哪一层"。
    ///
    /// **零失败也打**。一行不打的收尾没法区分"这一轮真的没失败"和"这个版本还没有
    /// 失败归因"，而这两种情况下用户该做的事完全不同（前者可以收工，后者要升级）。
    ///
    /// 时间列右对齐到本段的实际宽度：失败段的用法就是**竖着扫**，而 `4.995s` 和
    /// `1234.567s` 混在一段里时，左对齐会让工具名参差不齐、眼睛落不到同一列上。
    fn failures_section(&self, ev: &Summary) -> String {
        let n = ev.failures.len();
        if n == 0 {
            return format!("{}\n", colorize(&self.opts, DIM, "--- failures (0)"));
        }
        let origin = ev.first_wall.unwrap_or(0);
        let times: Vec<String> = ev.failures.iter().map(|f| rel_secs(f.ts_wall_ns, origin)).collect();
        let w = times.iter().map(|t| display_width(t)).max().unwrap_or(7).max(7);
        let mut s = String::new();
        s.push_str(&format!(
            "{}\n",
            colorize(&self.opts, RED, &format!("--- failures ({}):", n))
        ));
        for (f, t) in ev.failures.iter().zip(times.iter()) {
            // footer 是**第二个**输出口：时间线行在 `render_one` 的出口统一过
            // `one_line` 闸门，footer 之前没有。而这里承载的同样是不可信文本 ——
            // `f.tool` 直接来自 transcript（tool_use.name），`head`/`lineage`/
            // `claims`/`sniff` 来自结果文本。少了这一步，一个带 ESC 的 tool 名就能在
            // footer 里注入终端序列（改标题、清屏），而同一串在时间线行里是转义的。
            // 因此在进模板之前统一过同一个闸门；`one_line` 对已转义串是幂等的。
            let tool = crate::event::one_line(&f.tool);
            let cmd = crate::event::one_line(&f.cmd);
            let head = crate::event::one_line(&f.head);
            let deepest = f.deepest.as_deref().map(crate::event::one_line);
            // 先按**纯文本**限宽再上色。反过来会把转义序列算进列宽里，于是带颜色的
            // 那一版比无色版更早被截断 —— 同一个终端宽度下，`--no-color` 和默认
            // 输出会显示不同长度的命令，那是最难查的一类不一致。
            //
            // 列预算与时间线共用同一套分配（`fit_fail`）：footer 只是行首短得多，
            // 于是 `deepest` 通常能整段放下 —— 这正是"时间线上看不全的东西到
            // footer 里一定看得全"这句话的兑现方式。
            let prefix = format!("  {:>w$}  {} \"", t, tool, w = w);
            let body = fit_fail(
                &prefix,
                &cmd,
                &format!("\" -> {}", head),
                &match &deepest {
                    Some(d) => format!(" (deepest: {})", d),
                    None => String::new(),
                },
                MAX_COLS,
            );
            s.push_str(&format!("{}\n", colorize(&self.opts, RED, &body)));

            // v0.6 §14.1：血缘（产物从哪来、又到哪去）。
            //
            // 放在失败那一行的**下面**、缩进对齐到正文：它们是这条失败的注解，
            // 不是另一条失败。行文里的证据等级（`produced by step N`、
            // `userspace inference`）由 `lineage.rs` 生成，渲染层不加不减 ——
            // 这一层一旦"顺手润色"，屏幕上就会出现比账里更硬的话。
            for l in &f.lineage {
                let line = crate::event::one_line(l);
                s.push_str(&format!(
                    "{}\n",
                    colorize(&self.opts, DIM, &format!("{}{}", INDENT, line))
                ));
            }
            // v0.6 §14.2：其余几列对账。`!!` 的那一行已经在 `f.head` 里了，
            // 这里补的是同一次结果里的**其它** claim（一行结果可以既说写了文件
            // 又说下了 URL），它们不是失败，所以用暗色。
            for c in &f.claims {
                let line = crate::event::one_line(&c.render());
                // 第一列已经是这一行的 `head`（`-> claim: ... !!`）—— 再打一遍
                // 是同一句话说两次，而失败段的价值就在于每一行都值得读。
                if line == head {
                    continue;
                }
                s.push_str(&format!(
                    "{}\n",
                    colorize(
                        &self.opts,
                        if c.mismatch { RED } else { DIM },
                        &format!("{}{}", INDENT, line)
                    )
                ));
            }
            // v0.6 §14.3：内容嗅探。**用户态启发式** —— 句子自己带着这句话
            //（由 `lineage::sniff` 保证），这里只负责缩进。
            for x in &f.sniff {
                let line = crate::event::one_line(x);
                s.push_str(&format!(
                    "{}\n",
                    colorize(&self.opts, DIM, &format!("{}{}", INDENT, line))
                ));
            }
        }
        if !ev.kernel_available {
            // 段级限定语。逐行的 `head` 已经各自带了限定，这里再说一遍是为了让
            // "3 次失败、0 次能给出 deepest"这件事在**段**这一层就能被读懂 ——
            // 否则读的人会以为是归因算法没找到，而不是我们根本没在看内核。
            s.push_str(&format!(
                "{}\n",
                colorize(
                    &self.opts,
                    DIM,
                    "--- (no kernel capture this run: -p/-C absent or --source excluded it; \
                     `deepest` is not attributable)"
                )
            ));
        }
        s
    }
}

/// footer 里的相对秒数。`-` 表示没有可用的墙钟（fixture 相对时间、ts=0）。
fn rel_secs(ts_wall_ns: u64, origin: u64) -> String {
    if ts_wall_ns == 0 || origin == 0 || ts_wall_ns < origin {
        return "-".into();
    }
    format!("{:.3}s", (ts_wall_ns - origin) as f64 / 1e9)
}

#[derive(Default, Debug)]
pub struct Summary {
    pub total: u64,
    /// 首/末事件的墙钟（用于给出绝对时间跨度；openshell 下这是 `--time-base` 锚定后的值）。
    pub first_wall: Option<u64>,
    pub last_wall: Option<u64>,
    pub agent: u64,
    pub runtime: u64,
    pub infra: u64,
    pub policy: u64,
    pub derived: u64,
    pub late: u64,
    pub truncated: u64,
    pub lost: u64,
    /// 时间戳来源分布：内核直采 vs agent 换算。换算过的越多，
    /// 时间线的排序可信度越依赖那次 offset 采样（§1.4）。
    pub from_kernel: u64,
    pub from_agent: u64,
    pub binding: Option<Binding>,
    pub session: Option<String>,
    /// v0.2：折叠掉了多少条派生行、它们合计替换掉多少条原始行。
    ///
    /// 这是**保真度声明**而不是性能数字：折叠让屏幕上的行变少了，
    /// 如果不在收尾处说明"少的是被合并的，不是没采到的"，读者就无法区分
    /// "这里只有 1 次 exec" 和 "这里有 7 次 exec 被合并成 1 行"——而正是这个
    /// 区分决定了他要不要去 `-v` 里再看一遍。
    pub collapse_rows: u64,
    pub collapse_raw: u64,
    /// v0.4 §13：这一轮的失败账，footer 的 `--- failures (N)` 直接来自它。
    ///
    /// 与 `total` **刻意分开**。`total` 数的是"屏幕上打了几行"，这是铁律
    /// （`--- N events` 与逐层计数必须能对着屏幕数出来）。而失败列表回答的是
    /// "这一轮失败了几次"——它是一个**跨层结论**，`--failures-only` 下屏幕上
    /// 只剩失败链、默认模式下一条失败调用会同时贡献 `tool.call`/`tool.result`/
    /// `XX` 三行。把两者塞进同一个计数器，`--- N events` 立刻变成一句没法核对的话。
    pub failures: Vec<crate::fail::Failure>,
    /// 这一轮到底有没有在采集内核（`-p`/`-C` 且 `--source` 含内核维度）。
    ///
    /// 它决定失败段里那句限定语：**没在看内核的时候，不许说"内核里没有 X"**。
    pub kernel_available: bool,
}

impl Summary {
    pub fn observe(&mut self, ev: &Event) {
        self.total += 1;
        if ev.ts_wall_ns > 0 {
            self.first_wall = Some(match self.first_wall {
                Some(w) => w.min(ev.ts_wall_ns),
                None => ev.ts_wall_ns,
            });
            self.last_wall = Some(match self.last_wall {
                Some(w) => w.max(ev.ts_wall_ns),
                None => ev.ts_wall_ns,
            });
        }
        match ev.layer {
            Layer::Agent => self.agent += 1,
            Layer::Runtime => self.runtime += 1,
            Layer::Infra => self.infra += 1,
            Layer::Policy => self.policy += 1,
            Layer::Derived => self.derived += 1,
        }
        if ev.is_kernel() {
            self.from_kernel += 1;
        } else {
            self.from_agent += 1;
        }
        if ev.late {
            self.late += 1;
        }
        if !ev.trunc.is_empty() {
            self.truncated += 1;
        }
        if ev.kind == crate::event::Kind::CollectorLostEvents {
            self.lost += 1;
        }
    }
}

#[allow(dead_code)]
fn _unused(_: &str) -> String {
    RESET.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Binding, Corr, Kind, Layer, Payload, TsSource};

    fn ev(kind: Kind, layer: Layer, payload: Payload) -> Event {
        Event {
            seq: 1,
            ts_ns: 1_000_000_000,
            ts_wall_ns: 1_700_000_000_000_000_000,
            ts_src: TsSource::Kernel,
            layer,
            kind,
            source: "t".into(),
            pid: Some(644607),
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr::default(),
            payload,
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    #[test]
    fn columns_are_aligned() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::AgentModelRequest,
            Layer::Agent,
            Payload::ModelRequest {
                model: Some("deepseek-v4-pro".into()),
                input_tokens: Some(37382),
                detail_preview: None,
            },
        );
        let line = r.render_one(&e);
        // {rel:>13.6} 两空格 {layer:<8} 空格 {key:<9} 空格 {kind:<15} 空格 payload
        assert!(line.starts_with("     0.000000  agent    "), "{:?}", line);
        assert!(line.contains("model.request   deepseek-v4-pro  in=37382"), "{:?}", line);
    }

    #[test]
    fn long_header_note_is_word_cut_and_points_at_verbose() {
        // §3：横幅也算时间线，超宽必须截。但注记常常是保真度声明（比如 pid_binding
        // 为什么绑不上），在词中间砍掉会读成"话说一半"，所以必须是词边界 + 指向 -v。
        let note = "pid_binding=none: sessionId matches no `claude --resume` process; no claude \
                    process has a matching cwd and a start time inside the session window either";
        let h = Header {
            target: "pid 1 (tree)".into(),
            session: Some("8d3af668".into()),
            binding: Some(Binding::None),
            sources: vec!["bpftrace".into()],
            following: true,
            notes: vec![note.into()],
        };
        let out = TextRenderer::new(RenderOpts::default()).header(&h);
        let note_line = out
            .lines()
            .find(|l| l.contains("pid_binding=none"))
            .expect("note line present");
        assert!(
            crate::render::display_width(note_line) <= crate::render::MAX_COLS,
            "note must fit {} cols: {:?}",
            crate::render::MAX_COLS,
            note_line
        );
        assert!(note_line.ends_with("(full text under -v)"), "{:?}", note_line);
        assert!(!note_line.contains("~"), "注记不该用事件行的 `~` 记号: {:?}", note_line);
        // 完整原文仍然要能拿到 —— 截断的是显示，不是数据。
        assert!(out.contains("binding not exact"), "保真声明本身不能被挤掉: {:?}", out);
    }

    #[test]
    fn derived_layer_renders_as_bang_bang() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::CollectorLostEvents,
            Layer::Derived,
            Payload::LostEvents { count: 142 },
        );
        let line = r.render_one(&e);
        assert!(line.contains("!!"), "{:?}", line);
        assert!(line.contains("lost_events"), "{:?}", line);
        assert!(line.contains("N=142"), "{:?}", line);
        assert!(
            line.contains("kernel buffer overflow"),
            "丢包行必须解释发生了什么: {:?}",
            line
        );
    }

    #[test]
    fn markers_show_late_and_trunc() {
        let r = TextRenderer::new(RenderOpts::default());
        let mut e = ev(
            Kind::AgentToolCall,
            Layer::Agent,
            Payload::ToolCall {
                tool: "Bash".into(),
                input_preview: "x".into(),
                input_bytes: 1,
                via_mcp: false,
                bash_cmd: None,
            },
        );
        e.late = true;
        e.trunc
            .push(crate::event::TruncNote::new("input_preview", Some(900), 512));
        e.corr.pid_binding = Some(Binding::Heuristic);
        let line = r.render_one(&e);
        assert!(line.contains("(late)"), "{:?}", line);
        assert!(line.contains('~'), "{:?}", line);
        assert!(line.contains('?'), "binding 非 exact 时应有 ? 标记: {:?}", line);
    }

    /// `~` 只能表示"内容被截断"。notes 是说明性的 caveat，不能触发 `~`，
    /// 也不能计入"含截断"。实测：真实 transcript 上 model.request 的 ts 推导说明
    /// 曾被当成截断，让 489 条事件挂上 `~`，而其中绝大多数根本没有内容被截掉。
    #[test]
    fn notes_do_not_imply_truncation() {
        let r = TextRenderer::new(RenderOpts::default());
        let mut e = ev(
            Kind::AgentModelRequest,
            Layer::Agent,
            Payload::ModelRequest {
                model: None,
                input_tokens: None,
                detail_preview: None,
            },
        );
        e.notes.push("ts 是推导的".into());
        let line = r.render_one(&e);
        assert!(!line.contains('~'), "notes 不得产生 `~`: {:?}", line);

        let mut s = Summary::default();
        s.observe(&e);
        assert_eq!(s.truncated, 0, "notes 不得计入含截断");

        // 真正的截断依然要打 `~`
        let mut e2 = ev(
            Kind::AgentToolCall,
            Layer::Agent,
            Payload::ToolCall {
                tool: "Read".into(),
                input_preview: "x".into(),
                input_bytes: 9,
                via_mcp: false,
                bash_cmd: None,
            },
        );
        e2.trunc
            .push(crate::event::TruncNote::new("input_preview", Some(900), 512));
        assert!(r.render_one(&e2).contains('~'), "真截断必须打 `~`");
    }

    #[test]
    fn exact_binding_has_no_question_mark() {
        let r = TextRenderer::new(RenderOpts::default());
        let mut e = ev(
            Kind::AgentToolCall,
            Layer::Agent,
            Payload::ToolCall {
                tool: "Bash".into(),
                input_preview: "x".into(),
                input_bytes: 1,
                via_mcp: false,
                bash_cmd: None,
            },
        );
        e.corr.pid_binding = Some(Binding::Exact);
        assert!(!r.render_one(&e).contains('?'));
    }

    #[test]
    fn write_intent_flag_decoding() {
        // O_WRONLY|O_CREAT|O_TRUNC = 1|0o100|0o1000
        assert_eq!(super::super::decode_openat_flags(0o1101), "O_WRONLY|O_CREAT|O_TRUNC");
        assert_eq!(super::super::decode_openat_flags(0), "O_RDONLY");
        assert!(super::super::is_write_intent(0o1101));
        assert!(!super::super::is_write_intent(0));
    }

    #[test]
    fn relative_path_is_not_guessed() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::InfraFileOpen,
            Layer::Infra,
            Payload::FileOpen {
                path: "config.toml".into(),
                flags: 0o1,
                dirfd: 7,
                path_is_relative: true,
                ok: true,
                errno: 0,
            },
        );
        let line = r.render_one(&e);
        assert!(line.contains("rel dirfd=7"), "相对路径必须标明 dirfd: {:?}", line);
        // 这一行按 120 列上限被截断，被砍掉的尾部以 `~` 标记（§3）。
        assert!(line.ends_with('~'), "超宽行必须以 `~` 收尾: {:?}", line);
    }

    #[test]
    fn no_color_by_default() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::PolicyDeny,
            Layer::Policy,
            Payload::PolicyDeny {
                syscall: "openat".into(),
                target: "/etc/shadow".into(),
                errno: -13,
                errno_name: "EACCES".into(),
                decided_by: "kernel".into(),
            },
        );
        assert!(!r.render_one(&e).contains('\x1b'));
    }

    #[test]
    fn color_when_enabled() {
        let r = TextRenderer::new(RenderOpts {
            color: true,
            ..Default::default()
        });
        let e = ev(
            Kind::PolicyDeny,
            Layer::Policy,
            Payload::PolicyDeny {
                syscall: "openat".into(),
                target: "/etc/shadow".into(),
                errno: -13,
                errno_name: "EACCES".into(),
                decided_by: "kernel".into(),
            },
        );
        assert!(r.render_one(&e).contains("\x1b[31m"));
    }

    /// 中文截断后仍是合法 UTF-8，渲染不得 panic。
    #[test]
    fn cjk_payload_renders() {
        let r = TextRenderer::new(RenderOpts::default());
        let (cut, _, _) = crate::event::truncate_chars("读取密钥文件并上传到远程服务器", 12, 12);
        let e = ev(Kind::AgentModelText, Layer::Agent, Payload::ModelText { preview: cut });
        let line = r.render_one(&e);
        assert!(std::str::from_utf8(line.as_bytes()).is_ok());
    }

    /// 内核 argv 里的换行必须被转义：否则一行事件会被撕成两行，
    /// 定宽列与"一行一事件"同时失效（§3/§4.2）。
    #[test]
    fn argv_with_newlines_stays_on_one_row() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::RuntimeProcExec,
            Layer::Runtime,
            Payload::ProcExec {
                filename: "/bin/bash".into(),
                argv: vec!["bash".into(), "-c".into(), "echo a\necho b\t\u{7}".into()],
                argc_total: Some(3),
            },
        );
        let line = r.render_one(&e);
        assert!(!line.contains('\n'), "正文里不得出现裸换行: {:?}", line);
        assert!(line.contains("\\n"), "换行必须转义成可见的 \\n: {:?}", line);
        assert!(display_width(&line) <= MAX_COLS, "{:?}", line);
    }

    /// 不可信文本里的裸 `\x1b` 绝不能出现在输出里 —— 那是一个终端注入原语
    /// （改标题、清屏），而这些字符串来自 transcript / 内核，不是我们写的。
    /// 工具名走的是 `sfield`（不转义），正是这条闸门要拦的东西。
    #[test]
    fn escape_sequences_from_untrusted_text_never_reach_the_line() {
        for (color, verbose) in [(false, false), (true, true)] {
            let r = TextRenderer::new(RenderOpts {
                color,
                verbose,
                ..Default::default()
            });
            let mut e = ev(
                Kind::AgentToolCall,
                Layer::Agent,
                Payload::ToolCall {
                    tool: "\u{1b}]0;pwned\u{7}Bash".into(),
                    input_preview: "x".into(),
                    input_bytes: 1,
                    via_mcp: false,
                    bash_cmd: None,
                },
            );
            e.corr.tool_use_id = Some("\u{1b}[2Jid".into());
            let line = r.render_one(&e);
            // color=true 时颜色码本身是 ESC，所以只允许 `\x1b[` 这种自家开的码，
            // 绝不允许把载荷里的 ESC 原样打出去。
            assert!(
                !line.contains("\u{1b}]") && !line.contains("\u{1b}[2J"),
                "载荷里的控制序列必须被转义: {:?}",
                line
            );
            assert!(line.contains("\\x1b"), "转义要看得见: {:?}", line);
        }
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // 跳过 CSI 序列：ESC [ … 以一个字母收尾
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// §3：宽度按**显示列**算 —— CJK 一个字 2 列，既不是 1 也不是它的字节数。
    #[test]
    fn display_width_counts_cjk_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("中文"), 4);
        assert_eq!(display_width("中a"), 3);
        assert_eq!(super::super::char_width('，'), 2);
        // 组合记号不占列
        assert_eq!(display_width("e\u{0301}"), 1);
    }

    /// §3：默认任何一行都不超过 120 列；超长正文按字符边界截断并以 `~` 收尾。
    #[test]
    fn no_rendered_line_exceeds_120_columns() {
        let r = TextRenderer::new(RenderOpts::default());
        for preview in ["读".repeat(400), "a".repeat(400), "中文abc混合".repeat(60)] {
            let e = ev(Kind::AgentModelText, Layer::Agent, Payload::ModelText { preview });
            let line = r.render_one(&e);
            let w = display_width(&line);
            assert!(w <= MAX_COLS, "行宽 {} 列 > {}: {:?}", w, MAX_COLS, line);
            assert!(line.ends_with('~'), "被截断的行必须以 `~` 收尾: {:?}", line);
            assert!(std::str::from_utf8(line.as_bytes()).is_ok());
        }
    }

    /// 短行不得被无谓地砍（`~` 只在真的超宽时出现）。
    #[test]
    fn short_lines_are_left_alone() {
        let r = TextRenderer::new(RenderOpts::default());
        let e = ev(
            Kind::AgentModelText,
            Layer::Agent,
            Payload::ModelText {
                preview: "hello".into(),
            },
        );
        let line = r.render_one(&e);
        assert!(!line.contains('~'), "{:?}", line);
        assert!(line.ends_with("\"hello\""), "{:?}", line);
    }

    /// 着色不得影响列预算：ANSI 转义不是可见列。
    #[test]
    fn color_escapes_do_not_count_toward_the_column_budget() {
        let r = TextRenderer::new(RenderOpts {
            color: true,
            ..Default::default()
        });
        let mut e = ev(
            Kind::AgentModelText,
            Layer::Agent,
            Payload::ModelText {
                preview: "x".repeat(400),
            },
        );
        e.watch = true; // 整行标红 → 正文两侧都带上转义码
        let line = r.render_one(&e);
        let visible = strip_ansi(&line);
        assert!(
            display_width(&visible) <= MAX_COLS,
            "{} 列: {:?}",
            display_width(&visible),
            visible
        );
        assert!(visible.contains('~'), "正文被截断必须以 `~` 标记: {:?}", visible);
    }

    /// §3：重试行必须一行装得下（v0 里它换行换得最难看的一行）。
    #[test]
    fn retry_line_fits_on_one_row() {
        let r = TextRenderer::new(RenderOpts::default());
        let mut e = ev(
            Kind::DerivedToolRetry,
            Layer::Derived,
            Payload::Derived {
                label: "possible silent retry".into(),
                detail: "web_search x2 in 60s (first 2.5s ago)".into(),
                count: 0,
            },
        );
        e.retry = true;
        let line = r.render_one(&e);
        assert!(line.contains("!!"), "派生层用 ASCII 标记: {:?}", line);
        assert!(line.contains(" >>"), "疑似重试用 ASCII 标记: {:?}", line);
        assert!(
            line.contains("[possible silent retry] web_search x2 in 60s (first 2.5s ago)"),
            "{:?}",
            line
        );
        assert!(
            display_width(&line) <= MAX_COLS,
            "{} 列: {:?}",
            display_width(&line),
            line
        );
    }

    /// 标记全是 ASCII：定宽列在任何终端里都不会被宽字形推歪（§3）。
    #[test]
    fn markers_are_ascii_only() {
        let mut e = ev(
            Kind::AgentToolCall,
            Layer::Agent,
            Payload::ToolCall {
                tool: "Bash".into(),
                input_preview: "x".into(),
                input_bytes: 1,
                via_mcp: false,
                bash_cmd: None,
            },
        );
        e.late = true;
        e.retry = true;
        e.watch = true;
        e.corr.pid_binding = Some(Binding::Heuristic);
        e.trunc
            .push(crate::event::TruncNote::new("input_preview", Some(900), 512));
        let mk = markers(&e);
        assert!(mk.is_ascii(), "标记必须全 ASCII: {:?}", mk);
    }

    /// 一条长到能填满 footer 预算的失败记录。`tool` 由调用方给，方便测不可信文本。
    fn failure_fixture(tool: &str) -> crate::fail::Failure {
        crate::fail::Failure {
            ts_wall_ns: 1_700_000_000_000_000_000,
            ts_ns: 0,
            step: 1,
            tool: tool.to_string(),
            cmd: "a-very-long-command-".repeat(18),
            head: "exit 2 (deepest: openat /tmp/x ENOENT)".into(),
            deepest: Some("openat /tmp/x ENOENT".into()),
            class: "kernel".into(),
            detected_by: "status=Failure".into(),
            tool_use_id: None,
            kernel_events: 2,
            lineage: Vec::new(),
            claims: Vec::new(),
            sniff: Vec::new(),
        }
    }

    fn summary_with_failure(f: crate::fail::Failure) -> Summary {
        let mut s = Summary {
            total: 1,
            first_wall: Some(f.ts_wall_ns),
            last_wall: Some(f.ts_wall_ns),
            ..Default::default()
        };
        s.failures.push(f);
        s
    }

    /// footer 是**另一个**输出口：tool 名/结果文本来自不可信 transcript，必须和
    /// 时间线行一样过 `one_line` 闸门。回归用例：一个带 ESC 的 tool 名。
    #[test]
    fn footer_escapes_control_sequences_from_untrusted_text() {
        let r = TextRenderer::new(RenderOpts::default());
        let mut f = failure_fixture("Bash\u{1b}[2J\u{7}");
        f.lineage = vec!["input /tmp/x produced by step 1 Bash\u{1b}]0;pwned\u{7}".into()];
        f.sniff = vec!["(userspace heuristic) /tmp/x.pdf smells like HTML\u{1b}[2J".into()];
        let out = r.summary(&summary_with_failure(f));
        assert!(
            !out.contains('\u{1b}'),
            "footer 里不得出现裸 ESC（终端注入原语）: {:?}",
            out
        );
        assert!(out.contains("\\x1b[2J"), "转义后必须仍能看见原文: {:?}", out);
        assert!(out.contains("Bash"), "tool 名不能因为转义整段消失: {:?}", out);
    }

    /// §3 的 120 列上限按**可见列**算。summary 是先着色再 `cap_lines` 的，
    /// 若把 ANSI 当可见宽度，同一行在 tty（默认着色）上会比 `--no-color` 少
    /// 8–9 列并多出一个假的 `~`。修复后两者可见文本必须逐字节相同。
    #[test]
    fn colored_summary_keeps_the_same_visible_width_as_no_color() {
        let s = summary_with_failure(failure_fixture("Bash"));
        let plain = TextRenderer::new(RenderOpts::default()).summary(&s);
        let colored = TextRenderer::new(RenderOpts {
            color: true,
            ..Default::default()
        })
        .summary(&s);

        let visible = strip_ansi(&colored);
        assert_eq!(visible, plain, "着色不得改变可见文本（截断位置必须一致）");
        for (a, b) in visible.lines().zip(plain.lines()) {
            assert_eq!(display_width(a), display_width(b), "可见列宽不一致: {:?} vs {:?}", a, b);
        }
        assert!(
            plain.lines().any(|l| display_width(l) > 110),
            "测试必须真的碰到接近 120 列的 footer 行: {:?}",
            plain
        );
        assert!(
            plain.lines().all(|l| display_width(l) <= MAX_COLS),
            "footer 行超过 {} 列: {:?}",
            MAX_COLS,
            plain
        );
        // 被截断的彩色行不能在行尾留下半个转义序列。
        for line in colored.lines() {
            assert!(!line.ends_with('\u{1b}'), "半个转义序列: {:?}", line);
            assert!(!line.ends_with("\u{1b}["), "半个 CSI: {:?}", line);
        }
    }
}
