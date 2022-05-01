//! Kernel space probes.
use std::io;
use thiserror::Error;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_KPROBE,
    programs::{
        load_program,
        probe::{attach, ProbeKind},
        ProgramData, ProgramError,
    },
};

use super::{
    define_link_wrapper,
    perf_attach::{PerfLink, PerfLinkId},
};

/// A kernel probe.
///
/// Kernel probes are eBPF programs that can be attached to almost any function inside
/// the kernel. They can be of two kinds:
///
/// - `kprobe`: get attached to the *start* of the target functions
/// - `kretprobe`: get attached to the *return address* of the target functions
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.1.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::KProbe};
/// use std::convert::TryInto;
///
/// let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
/// program.load()?;
/// program.attach("try_to_wake_up", 0)?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct KProbe {
    pub(crate) data: ProgramData<KProbeLink>,
    pub(crate) kind: ProbeKind,
}

impl KProbe {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Returns `KProbe` if the program is a `kprobe`, or `KRetProbe` if the
    /// program is a `kretprobe`.
    pub fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program.
    ///
    /// Attaches the probe to the given function name inside the kernel. If
    /// `offset` is non-zero, it is added to the address of the target
    /// function.
    ///
    /// If the program is a `kprobe`, it is attached to the *start* address of the target function.
    /// Conversely if the program is a `kretprobe`, it is attached to the return address of the
    /// target function.
    ///
    /// The returned value can be used to detach from the given function, see [KProbe::detach].
    pub fn attach(&mut self, fn_name: &str, offset: u64) -> Result<KProbeLinkId, ProgramError> {
        attach(&mut self.data, self.kind, fn_name, offset, None)
    }

    /// Detaches the program.
    ///
    /// See [KProbe::attach].
    pub fn detach(&mut self, link_id: KProbeLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    KProbeLink,
    /// The type returned by [KProbe::attach]. Can be passed to [KProbe::detach].
    KProbeLinkId,
    PerfLink,
    PerfLinkId
);

/// The type returned when attaching a [`KProbe`] fails.
#[derive(Debug, Error)]
pub enum KProbeError {
    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: String,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },
}
