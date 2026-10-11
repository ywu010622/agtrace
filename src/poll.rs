//! collector 与 adapter 共享的轮询结果词汇（DESIGN.md §3.1）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// 本次没有新行（正常，不是错误）。
    Idle,
    /// 有新事件。
    Progress,
    /// 源已结束（文件被删除且不再出现 / 离线 fixture 读完）。
    Eof,
}
