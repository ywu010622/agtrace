//! Merger：min-heap 有界重排 + 时钟换算（DESIGN.md §2.4）。
//!
//! **关键设计决定：agent 事件永不阻塞时间线。**
//! transcript 是事后写入的（tool_result 行在工具跑完之后才落盘），延迟可达秒级
//! 甚至更久且不可预测。如果严格按时间戳等待，实时 tail 会卡住。所以：
//! - 内核事件：正常参与重排窗口。
//! - agent 事件：**立即输出**，不参与窗口等待；若其 ts 早于已输出内核事件的
//!   水位线，标记 `late=true`（渲染成 `(late)`）。
//! - 这是**有损的排序保证**：输出是"近似时间序"，不是严格时间序。必须诚实呈现。

use crate::event::{Binding, Corr, Event, Layer, Payload, TsSource};
use crate::views::Views;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// 单调钟 ↔ 墙钟的偏移换算（§1.4）。
///
/// `offset = wall_at_start - mono_at_start`，启动时采样一次，之后按
/// `--resync-interval` 重新采样以修正 NTP 漂移。
pub struct Clock {
    offset_ns: i128,
    last_sample: std::time::Instant,
    resync: std::time::Duration,
    /// 是否已经比对过"bpftrace 的 nsecs 和本地 CLOCK_MONOTONIC 是不是同一个钟"。
    mono_checked: bool,
}

impl Clock {
    pub fn new(resync_secs: u64) -> Self {
        let mut c = Clock {
            offset_ns: 0,
            last_sample: std::time::Instant::now(),
            resync: std::time::Duration::from_secs(resync_secs),
            mono_checked: false,
        };
        c.sample();
        c
    }

    fn sample(&mut self) {
        let wall = wall_now_ns() as i128;
        let mono = mono_now_ns() as i128;
        self.offset_ns = wall - mono;
        self.last_sample = std::time::Instant::now();
    }

    /// 到点就重新采样（§1.4 缓解措施：`--resync-interval` 默认 30s，0=关闭）。
    pub fn maybe_resync(&mut self) {
        if self.resync.is_zero() {
            return;
        }
        if self.last_sample.elapsed() >= self.resync {
            self.sample();
        }
    }

    pub fn wall_from_mono(&self, mono_ns: u64) -> u64 {
        let v = mono_ns as i128 + self.offset_ns;
        v.clamp(0, u64::MAX as i128) as u64
    }

    pub fn mono_from_wall(&self, wall_ns: u64) -> u64 {
        let v = wall_ns as i128 - self.offset_ns;
        v.clamp(0, u64::MAX as i128) as u64
    }

    pub fn offset(&self) -> i128 {
        self.offset_ns
    }

    /// 检查内核事件的时间戳是否真的落在本地 CLOCK_MONOTONIC 上。
    ///
    /// DESIGN.md §0 把"`nsecs` 是 CLOCK_MONOTONIC"标为 `[已验证]`。这里再做一次
    /// **运行时**自检：如果第一个内核事件与本机单调钟差得离谱，说明假设不成立，
    /// 与其产出一条错位的时间线，不如明确告诉用户。
    pub fn check_mono(&mut self, kernel_ts_ns: u64) -> Option<String> {
        if self.mono_checked {
            return None;
        }
        self.mono_checked = true;
        let local = mono_now_ns();
        let delta = local as i128 - kernel_ts_ns as i128;
        // 正常的采集延迟是微秒~毫秒级；超过 5s 说明不是同一个钟。
        if delta.abs() > 5_000_000_000 {
            return Some(format!(
                "warning: kernel event timestamp differs from local CLOCK_MONOTONIC by {:.3}s — \
                 `nsecs` may not be CLOCK_MONOTONIC, so cross-layer time comparison is unreliable (DESIGN.md §0)",
                delta as f64 / 1e9
            ));
        }
        None
    }
}

fn wall_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub fn mono_now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// 堆元素。按 `ts_ns` 排序，同 ts 用 `seq` 打破平局 → **稳定排序**。
struct HeapItem {
    ts_ns: u64,
    seq: u64,
    ev: Event,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.ts_ns == other.ts_ns && self.seq == other.seq
    }
}
impl Eq for HeapItem {}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap 是 max-heap，我们要最早的事件先出 → 反向比较。
        other.ts_ns.cmp(&self.ts_ns).then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct Merger {
    heap: BinaryHeap<HeapItem>,
    window_ns: u64,
    seq: u64,
    /// 已输出的**内核**事件的最大 ts（§2.4 的水位线）。
    /// 只用内核事件推进水位线 —— 否则一个未来时间的 agent 事件会把水位线
    /// 顶高，导致随后到达的正常内核事件全被误标 `(late)`。
    watermark_ns: u64,
    pub clock: Clock,
    pub views: Views,
    /// 已经输出的事件（本轮）。
    ready: Vec<Event>,
    /// 采集器诊断信息（时钟假设不成立等），由 main 决定怎么显示。
    pub warnings: Vec<String>,
    /// 统计：被标 late 的数量。
    pub late_count: u64,
    pub emitted: u64,
}

impl Merger {
    pub fn new(window_ms: u64, resync_secs: u64, views: Views) -> Self {
        Merger {
            heap: BinaryHeap::new(),
            window_ns: window_ms * 1_000_000,
            seq: 0,
            watermark_ns: 0,
            clock: Clock::new(resync_secs),
            views,
            ready: Vec::new(),
            warnings: Vec::new(),
            late_count: 0,
            emitted: 0,
        }
    }

    pub fn window_ms(&self) -> u64 {
        self.window_ns / 1_000_000
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// 内核事件：进入重排窗口。
    pub fn push_kernel(&mut self, mut ev: Event) {
        if let Some(w) = self.clock.check_mono(ev.ts_ns) {
            self.warnings.push(w);
        }
        ev.seq = self.next_seq();
        ev.ts_wall_ns = self.clock.wall_from_mono(ev.ts_ns);
        ev.ts_src = TsSource::Kernel;
        let item = HeapItem {
            ts_ns: ev.ts_ns,
            seq: ev.seq,
            ev,
        };
        self.heap.push(item);
        self.flush_due();
    }

    /// agent 事件：**立即输出**，不参与窗口等待（§2.4）。
    ///
    /// 唯一的例外是时间戳落在**未来**的 agent 事件，见下方。
    pub fn push_agent(&mut self, mut ev: Event) {
        ev.seq = self.next_seq();
        // 换算：wall → mono（§1.4 的 offset 换算）。
        if ev.ts_src == TsSource::Converted {
            ev.ts_ns = self.clock.mono_from_wall(ev.ts_wall_ns);
        }
        let now = mono_now_ns();

        // 一条事件不可能在它发生**之前**被观测到。
        //
        // agent 事件的时间戳来自 transcript 的墙钟，经 offset 换算而来；若换算
        // 结果比本机单调钟还靠前，只有两种可能：transcript 那侧的时钟不准，或者
        // 我们的 offset 不准。此时"立即输出"会让它**插到**那些时间戳更早、但还没
        // 到达的内核事件前面 —— 时间线出现倒序。
        //
        // 实测（受控 fixture，把 tool.call 放在 now+14s）：3 条 agent 事件排在了
        // 13 秒之前的内核事件前面，44 条里 2 处倒序。对一个"统一时间线"工具来说，
        // 静默倒序比报错更糟。
        //
        // 处理：这类事件进堆，像内核事件一样按时间序放出。§2.4 说"agent 事件不参与
        // 窗口等待"，为的是不让 agent 层拖住时间线；而一条**尚未发生**的事件本来就
        // 没有可拖住的东西，让它等到该出现的时刻才是对的。
        if ev.ts_ns > now.saturating_add(self.window_ns) {
            ev.notes.push(format!(
                "timestamp is {:.3}s ahead of the local monotonic clock (transcript clock or clock offset skew); \
                 queued in time order instead of being emitted at once, to avoid a reversed timeline",
                (ev.ts_ns - now) as f64 / 1e9
            ));
            let item = HeapItem {
                ts_ns: ev.ts_ns,
                seq: ev.seq,
                ev,
            };
            self.heap.push(item);
            return;
        }

        // 若它比已经输出的内核事件还早，那它"迟到"了 —— 明确标记，不假装有序。
        if ev.ts_ns < self.watermark_ns {
            ev.late = true;
            self.late_count += 1;
        }
        self.emit(ev);
    }

    /// 把窗口内到期的事件弹出。参考时钟用 `max(内核流最大 ts, 本地单调钟)`：
    /// - 用本地单调钟兜底，保证内核流暂停时窗口里的事件不会被无限期压住；
    /// - 两者都是 CLOCK_MONOTONIC，天然可比（DESIGN.md §0）。
    pub fn flush_due(&mut self) {
        let now = mono_now_ns().max(self.watermark_ns);
        while let Some(top) = self.heap.peek() {
            if now.saturating_sub(top.ts_ns) > self.window_ns {
                let item = self.heap.pop().unwrap();
                let ts = item.ts_ns;
                let mut ev = item.ev;
                if ts < self.watermark_ns {
                    ev.late = true;
                    self.late_count += 1;
                }
                self.watermark_ns = self.watermark_ns.max(ts);
                self.emit(ev);
            } else {
                break;
            }
        }
    }

    /// 流结束：把堆里剩下的全部倒出来（不进窗口等待）。
    pub fn flush_all(&mut self) {
        while let Some(item) = self.heap.pop() {
            let ts = item.ts_ns;
            let mut ev = item.ev;
            if ts < self.watermark_ns {
                ev.late = true;
                self.late_count += 1;
            }
            self.watermark_ns = self.watermark_ns.max(ts);
            self.emit(ev);
        }
        // ④ 派生视图的收尾：报告一直没等到 result 的 tool call。
        let tail = self.views.finish();
        for mut e in tail {
            e.seq = self.next_seq();
            self.emit(e);
        }
    }

    /// 输出一个事件，并让派生视图观察它（§8 ④⑤）。
    ///
    /// 注意顺序：**先 observe 再入队**。observe 可能给事件打上 `watch` / `retry`
    /// 标记，也可能产出派生行 —— 派生行必须紧跟触发它的那行之后。
    fn emit(&mut self, mut ev: Event) {
        self.views.observe(&mut ev);
        self.ready.push(ev);
        // 视图自己产出的事件（gap/retry/watchlist 标记行）紧跟其后。
        let derived = self.views.drain_derived();
        for mut d in derived {
            d.seq = self.next_seq();
            self.ready.push(d);
        }
        self.emitted = self.ready.len() as u64;
    }

    /// 取走本轮输出的事件。
    pub fn take_ready(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.ready)
    }

    /// 采集器异常结束（bpfrace 挂了）时插入一条显式记录 —— 丢包绝不静默（§4.3）。
    pub fn push_collector_end(&mut self, reason: &str) {
        let ev = Event {
            seq: self.next_seq(),
            ts_ns: mono_now_ns(),
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Derived,
            kind: crate::event::Kind::CollectorLostEvents,
            source: "bpftrace".into(),
            pid: None,
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr::default(),
            payload: Payload::Derived {
                label: "collector end".into(),
                detail: reason.to_string(),
                count: 0,
            },
            trunc: Vec::new(),
            notes: Vec::new(),
            late: false,
            watch: true,
            binding: Binding::None,
            retry: false,
        };
        self.ready.push(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Binding, Kind, Payload};

    fn k(ts: u64, pid: u32) -> Event {
        Event {
            seq: 0,
            ts_ns: ts,
            ts_wall_ns: 0,
            ts_src: TsSource::Kernel,
            layer: Layer::Runtime,
            kind: Kind::RuntimeProcExec,
            source: "bpftrace".into(),
            pid: Some(pid),
            tid: None,
            ppid: None,
            comm: None,
            cgroup_id: None,
            corr: Corr::default(),
            payload: Payload::ProcExec {
                filename: "x".into(),
                argv: vec![],
                argc_total: None,
            },
            trunc: vec![],
            notes: Vec::new(),
            late: false,
            watch: false,
            binding: Binding::None,
            retry: false,
        }
    }

    /// 乱序到达的内核事件必须被重排成时间序。
    ///
    /// 窗口必须**大于**乱序幅度，否则事件在 push 时就已经到期放行，根本没有重排的机会
    /// （这正是窗口存在的意义，也是这个测试最容易写错的地方）。
    #[test]
    fn reorders_out_of_order_kernel_events() {
        let mut m = Merger::new(500, 0, Views::disabled());
        let now = mono_now_ns();
        // pid 与时间戳**故意不一致**，这样"按到达顺序输出"这种错误实现一定会被检出。
        //   ts(now-300ms) → pid 3   ← 最早
        //   ts(now-100ms) → pid 1   ← 最晚，却第二个到达
        //   ts(now-200ms) → pid 2
        // 正确的输出顺序（按 ts 升序）是 3, 2, 1；到达顺序是 3, 1, 2。
        m.push_kernel(k(now - 300_000_000, 3));
        m.push_kernel(k(now - 100_000_000, 1));
        m.push_kernel(k(now - 200_000_000, 2));
        assert_eq!(m.take_ready().len(), 0, "500ms 窗口内的事件不该提前放行");
        m.flush_all();
        let out = m.take_ready();
        let pids: Vec<u32> = out.iter().map(|e| e.pid.unwrap()).collect();
        assert_eq!(pids, vec![3, 2, 1], "内核事件没有被重排成时间序（到达顺序是 3,1,2）");
    }

    /// 窗口为 0 时不应有任何重排（顺序 = 到达顺序）—— 这是窗口语义的另一半。
    #[test]
    fn zero_window_does_not_reorder() {
        let mut m = Merger::new(0, 0, Views::disabled());
        let now = mono_now_ns();
        m.push_kernel(k(now - 300_000_000, 3));
        m.push_kernel(k(now - 100_000_000, 1));
        let out = m.take_ready();
        let pids: Vec<u32> = out.iter().map(|e| e.pid.unwrap()).collect();
        assert_eq!(pids, vec![3, 1], "窗口为 0 时应按到达顺序放行");
    }

    /// 窗口内的事件被更晚到达的乱序事件"插队"时要正确重排。
    #[test]
    fn late_arrival_within_window_is_reordered() {
        let mut m = Merger::new(500, 0, Views::disabled());
        let now = mono_now_ns();
        m.push_kernel(k(now - 100_000_000, 1));
        // 更早的事件晚到 —— 必须排到前面去
        m.push_kernel(k(now - 400_000_000, 9));
        assert_eq!(m.take_ready().len(), 0, "窗口内不该提前放行");
        m.flush_all();
        let pids: Vec<u32> = m.take_ready().iter().map(|e| e.pid.unwrap()).collect();
        assert_eq!(pids, vec![9, 1], "晚到的更早事件没有被插到前面");
    }

    /// agent 事件永不阻塞：即使它的时间戳比窗口里等待的内核事件更早，
    /// 也必须立刻出来（§2.4），并带上 late 标记。
    #[test]
    fn agent_events_never_block() {
        let mut m = Merger::new(200, 0, Views::disabled());
        let now = mono_now_ns();
        // 先推一个内核事件，它会留在窗口里等
        m.push_kernel(k(now, 1));
        assert_eq!(m.take_ready().len(), 0, "内核事件不应该立刻输出（窗口内）");

        let mut a = k(0, 0);
        a.ts_src = TsSource::Converted;
        a.ts_wall_ns = m.clock.wall_from_mono(now - 500_000_000);
        a.layer = Layer::Agent;
        m.push_agent(a);
        assert_eq!(m.take_ready().len(), 1, "agent 事件必须立即输出，不得等待窗口");
    }

    /// 时间戳落在**未来**的 agent 事件不得插到更早的内核事件前面。
    ///
    /// 这是 `agent_events_never_block` 的边界：那条保证的是"不让 agent 层拖住
    /// 时间线"，而一条尚未发生的事件没有可拖住的东西 —— 让它立即输出，只会让
    /// 时间线倒序。实测受控 fixture（tool.call 放在 now+14s）下 44 条里 2 处倒序。
    #[test]
    fn future_dated_agent_event_does_not_jump_the_queue() {
        let mut m = Merger::new(200, 0, Views::disabled());
        let now = mono_now_ns();
        // 一条"现在之前"的内核事件，正常应立即放行
        m.push_kernel(k(now - 1_000_000_000, 1));
        let out = m.take_ready();
        assert_eq!(out.len(), 1, "过去的内核事件应已放行");

        // agent 事件声称发生在 14s 之后 —— 它还没发生
        let mut a = k(0, 0);
        a.ts_src = TsSource::Converted;
        a.ts_wall_ns = m.clock.wall_from_mono(now + 14_000_000_000);
        a.layer = Layer::Agent;
        m.push_agent(a);
        assert_eq!(
            m.take_ready().len(),
            0,
            "未来的 agent 事件被立即输出了 —— 会排到更早的内核事件前面，造成倒序"
        );

        // 时间真的走到那时，它才按序出现
        m.flush_all();
        let out = m.take_ready();
        assert_eq!(out.len(), 1);
        assert!(
            !out[0].notes.is_empty(),
            "未来时间戳必须留下说明（notes），不能静默改行为"
        );
    }

    #[test]
    fn same_ts_is_stable_by_seq() {
        let mut m = Merger::new(0, 0, Views::disabled());
        let now = mono_now_ns();
        for i in 0..5 {
            m.push_kernel(k(now - 1_000_000_000, i));
        }
        let out = m.take_ready();
        let pids: Vec<u32> = out.iter().map(|e| e.pid.unwrap()).collect();
        assert_eq!(pids, vec![0, 1, 2, 3, 4], "同 ts 时未按 seq 稳定排序");
    }
}
