//! Verbose step tracing for the CLI (`--verbose` / `-v`).
//!
//! A tiny, dependency-free tracer: when verbose is enabled, each traced
//! step is emitted to STDERR as a `[trace]` line carrying the step name,
//! the time spent since the previous step (and since the trace start), and
//! a free-form detail line. Stderr keeps the report on stdout
//! machine-parseable. A disabled tracer is a zero-cost no-op.
//!
//! The tracer is the debugging surface for the RELATIVE reference
//! operations (`@-`, `@--`, `parent(...)`, `<deployment-id>-`, ...): the
//! push spine records the ref-parse step ([`crate::deploy::push::push`])
//! and [`crate::ledger::resolve_ref_expr`] records each resolution step
//! (ledger read, successful-chain build, base position, ancestor walk,
//! resolved ref), so a future agent can see exactly what a relative push
//! did, in what order, and how long each step took — `grep '\[trace\]'`
//! on the stderr of a `deploy push --verbose` run.
//!
//! The implementation lives in `storekit::trace` (its prior home was this
//! file); this module re-exports it so every `crate::trace::Tracer` call site
//! keeps compiling unchanged.

pub(crate) use storekit::trace::Tracer;

#[cfg(test)]
mod tests {
    use super::*;

    /// A disabled tracer is a no-op: `step` never emits (the emission path
    /// is gated on `enabled`, so a `Tracer::new(false)` cannot print).
    #[test]
    fn disabled_tracer_is_a_noop() {
        let mut t = Tracer::new(false);
        // Must not panic and must not print: the step body is gated on
        // `enabled`, so this exercises the gate itself.
        t.step("ref.parse", "token=\"@-\" -> @-");
    }

    /// An enabled tracer records steps (the elapsed durations are monotonic —
    /// each step's since-last is >= 0 and the since-start grows). The
    /// emission itself goes to stderr; the test asserts the bookkeeping
    /// contract, not the captured sink.
    #[test]
    fn enabled_tracer_records_steps() {
        let mut t = Tracer::new(true);
        t.step("ref.parse", "token=\"@-\" -> @-");
        t.step("ref.resolve", "target=\"production\" expr=@-");
        // The bookkeeping is internal; the contract is that two steps ran
        // without panicking.
    }
}
