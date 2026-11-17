//! A library caller cannot forge a process group: the group's authority is the
//! [`ProcessGroup`] CAPABILITY, minted only by spawning through it. A bare pid
//! is what the old `kill_process_group(pgid, sig)` entry point accepted, and
//! the kernel recycles that number the instant its child is reaped.
//!
//! The witnesses are declared HERE rather than taken from the substrate's own
//! signatures: a note quoting a git dependency's source renders with an
//! absolute checkout path this snapshot could never pin.

use deploy::remote::transport::ProcessGroup;

/// Demands the CAPABILITY where a pid would otherwise be accepted.
fn requires_group(_group: &ProcessGroup) {}

fn main() {
    let pgid: i32 = 4242;
    // ERROR: a pid is not a group — the signalling surface takes the capability.
    requires_group(pgid);
    // ERROR: and no group is minted from a number.
    let _group: ProcessGroup = pgid;
}
