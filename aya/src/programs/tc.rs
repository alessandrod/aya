//! Network traffic control programs.
use thiserror::Error;

use std::{
    ffi::{CStr, CString},
    io,
};

use crate::{
    generated::{
        bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS, TC_H_CLSACT, TC_H_MIN_EGRESS, TC_H_MIN_INGRESS,
    },
    programs::{load_program, Link, ProgramData, ProgramError},
    sys::{
        netlink_find_filter_with_name, netlink_qdisc_add_clsact, netlink_qdisc_attach,
        netlink_qdisc_detach,
    },
    util::{ifindex_from_ifname, tc_handler_make},
};

use super::define_link_wrapper;

/// Traffic control attach type.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum TcAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
    /// Attach to custom parent.
    Custom(u32),
}

/// A network traffic control classifier.
///
/// [`SchedClassifier`] programs can be used to inspect, filter or redirect
/// network packets in both ingress and egress. They are executed as part of the
/// linux network traffic control system. See
/// [https://man7.org/linux/man-pages/man8/tc-bpf.8.html](https://man7.org/linux/man-pages/man8/tc-bpf.8.html).
///
/// # Examples
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.1.
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
/// use aya::programs::{tc, SchedClassifier, TcAttachType};
///
/// // the clsact qdisc needs to be added before SchedClassifier programs can be
/// // attached
/// tc::qdisc_add_clsact("eth0")?;
///
/// let prog: &mut SchedClassifier = bpf.program_mut("redirect_ingress").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("eth0", TcAttachType::Ingress)?;
///
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SCHED_CLS")]
pub struct SchedClassifier {
    pub(crate) data: ProgramData<SchedClassifierLink>,
    pub(crate) name: Box<CStr>,
}

/// Errors from TC programs
#[derive(Debug, Error)]
pub enum TcError {
    /// netlink error while attaching ebpf program
    #[error("netlink error while attaching ebpf program to tc")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: io::Error,
    },
    /// the clsact qdisc is already attached
    #[error("the clsact qdisc is already attached")]
    AlreadyAttached,
}

impl TcAttachType {
    pub(crate) fn parent(&self) -> u32 {
        match self {
            TcAttachType::Custom(parent) => *parent,
            TcAttachType::Ingress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_INGRESS),
            TcAttachType::Egress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_EGRESS),
        }
    }
}

impl SchedClassifier {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SCHED_CLS, &mut self.data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// The returned value can be used to detach, see [SchedClassifier::detach].
    ///
    /// # Errors
    ///
    /// [`TcError::NetlinkError`] is returned if attaching fails. A common cause
    /// of failure is not having added the `clsact` qdisc to the given
    /// interface, see [`qdisc_add_clsact`]
    ///
    pub fn attach(
        &mut self,
        interface: &str,
        attach_type: TcAttachType,
    ) -> Result<SchedClassifierLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let if_index = ifindex_from_ifname(interface)
            .map_err(|io_error| TcError::NetlinkError { io_error })?;
        let priority =
            unsafe { netlink_qdisc_attach(if_index as i32, &attach_type, prog_fd, &self.name) }
                .map_err(|io_error| TcError::NetlinkError { io_error })?;

        Ok(self.data.links.insert(SchedClassifierLink(TcLink {
            if_index: if_index as i32,
            attach_type,
            priority,
        })))
    }

    /// Detaches the program.
    ///
    /// See [SchedClassifier::attach].
    pub fn detach(&mut self, link_id: SchedClassifierLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct TcLinkId(i32, TcAttachType, u32);

#[derive(Debug)]
struct TcLink {
    if_index: i32,
    attach_type: TcAttachType,
    priority: u32,
}

impl Link for TcLink {
    type Id = TcLinkId;

    fn id(&self) -> Self::Id {
        TcLinkId(self.if_index, self.attach_type, self.priority)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe { netlink_qdisc_detach(self.if_index, &self.attach_type, self.priority) }
            .map_err(|io_error| TcError::NetlinkError { io_error })?;
        Ok(())
    }
}

define_link_wrapper!(
    SchedClassifierLink,
    /// The type returned by [SchedClassifier::attach]. Can be passed to [SchedClassifier::detach].
    SchedClassifierLinkId,
    TcLink,
    TcLinkId
);

/// Add the `clasct` qdisc to the given interface.
///
/// The `clsact` qdisc must be added to an interface before [`SchedClassifier`]
/// programs can be attached.
pub fn qdisc_add_clsact(if_name: &str) -> Result<(), io::Error> {
    let if_index = ifindex_from_ifname(if_name)?;
    unsafe { netlink_qdisc_add_clsact(if_index as i32) }
}

/// Detaches the programs with the given name.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] to indicate that no programs with the
/// given name were found, so nothing was detached. Other error kinds indicate
/// an actual failure while detaching a program.
pub fn qdisc_detach_program(
    if_name: &str,
    attach_type: TcAttachType,
    name: &str,
) -> Result<(), io::Error> {
    let cstr = CString::new(name)?;
    qdisc_detach_program_fast(if_name, attach_type, &cstr)
}

/// Detaches the programs with the given name as a C string.
/// Unlike qdisc_detach_program, this function does not allocate an additional
/// CString to.
///
/// # Errors
///
/// Returns [`io::ErrorKind::NotFound`] to indicate that no programs with the
/// given name were found, so nothing was detached. Other error kinds indicate
/// an actual failure while detaching a program.
fn qdisc_detach_program_fast(
    if_name: &str,
    attach_type: TcAttachType,
    name: &CStr,
) -> Result<(), io::Error> {
    let if_index = ifindex_from_ifname(if_name)? as i32;

    let prios = unsafe { netlink_find_filter_with_name(if_index, attach_type, name)? };
    if prios.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            name.to_string_lossy(),
        ));
    }

    for prio in prios {
        unsafe { netlink_qdisc_detach(if_index, &attach_type, prio)? };
    }

    Ok(())
}
