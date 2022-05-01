use std::{fs, io};
use thiserror::Error;

use crate::{generated::bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT, sys::perf_event_open_trace_point};

use super::{
    define_link_wrapper, load_program,
    perf_attach::{perf_attach, PerfLink, PerfLinkId},
    ProgramData, ProgramError,
};

/// The type returned when attaching a [`TracePoint`] fails.
#[derive(Debug, Error)]
pub enum TracePointError {
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

/// A program that can be attached at a pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.7.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::convert::TryInto;
/// use aya::programs::TracePoint;
///
/// let prog: &mut TracePoint = bpf.program_mut("trace_context_switch").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("sched", "sched_switch")?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_TRACEPOINT")]
pub struct TracePoint {
    pub(crate) data: ProgramData<TracePointLink>,
}

impl TracePoint {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_TRACEPOINT, &mut self.data)
    }

    /// Attaches to a given trace point.
    ///
    /// For a list of the available event categories and names, see
    /// `/sys/kernel/debug/tracing/events`.
    ///
    /// The returned value can be used to detach, see [TracePoint::detach].
    pub fn attach(&mut self, category: &str, name: &str) -> Result<TracePointLinkId, ProgramError> {
        let id = read_sys_fs_trace_point_id(category, name)?;
        let fd = perf_event_open_trace_point(id, None).map_err(|(_code, io_error)| {
            ProgramError::SyscallError {
                call: "perf_event_open".to_owned(),
                io_error,
            }
        })? as i32;

        perf_attach(&mut self.data, fd)
    }

    /// Detaches from a trace point.
    ///
    /// See [TracePoint::attach].
    pub fn detach(&mut self, link_id: TracePointLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    TracePointLink,
    /// The type returned by [TracePoint::attach]. Can be passed to [TracePoint::detach].
    TracePointLinkId,
    PerfLink,
    PerfLinkId
);

pub(crate) fn read_sys_fs_trace_point_id(
    category: &str,
    name: &str,
) -> Result<u32, TracePointError> {
    let file = format!("/sys/kernel/debug/tracing/events/{}/{}/id", category, name);

    let id = fs::read_to_string(&file).map_err(|io_error| TracePointError::FileError {
        filename: file.clone(),
        io_error,
    })?;
    let id = id
        .trim()
        .parse::<u32>()
        .map_err(|error| TracePointError::FileError {
            filename: file.clone(),
            io_error: io::Error::new(io::ErrorKind::Other, error),
        })?;

    Ok(id)
}
