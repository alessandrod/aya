//! eBPF program types.
//!
//! eBPF programs are loaded inside the kernel and attached to one or more hook
//! points. Whenever the hook points are reached, the programs are executed.
//!
//! # Loading and attaching programs
//!
//! When you call [`Bpf::load_file`] or [`Bpf::load`], all the programs included
//! in the object code are parsed and relocated. Programs are not loaded
//! automatically though, since often you will need to do some application
//! specific setup before you can actually load them.
//!
//! In order to load and attach a program, you need to retrieve it using [`Bpf::program_mut`],
//! then call the `load()` and `attach()` methods, for example:
//!
//! ```no_run
//! use aya::{Bpf, programs::KProbe};
//! use std::convert::TryInto;
//!
//! let mut bpf = Bpf::load_file("ebpf_programs.o")?;
//! // intercept_wakeups is the name of the program we want to load
//! let program: &mut KProbe = bpf.program_mut("intercept_wakeups").unwrap().try_into()?;
//! program.load()?;
//! // intercept_wakeups will be called every time try_to_wake_up() is called
//! // inside the kernel
//! program.attach("try_to_wake_up", 0)?;
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! The signature of the `attach()` method varies depending on what kind of
//! program you're trying to attach.
//!
//! [`Bpf::load_file`]: crate::Bpf::load_file
//! [`Bpf::load`]: crate::Bpf::load
//! [`Bpf::programs`]: crate::Bpf::programs
//! [`Bpf::program`]: crate::Bpf::program
//! [`Bpf::program_mut`]: crate::Bpf::program_mut
//! [`maps`]: crate::maps
mod cgroup_skb;
mod extension;
mod fentry;
mod fexit;
mod kprobe;
mod lirc_mode2;
mod lsm;
mod perf_attach;
pub mod perf_event;
mod probe;
mod raw_trace_point;
mod sk_msg;
mod sk_skb;
mod sock_ops;
mod socket_filter;
pub mod tc;
mod tp_btf;
mod trace_point;
mod uprobe;
mod utils;
mod xdp;

use libc::{close, dup, ENOSPC};
use std::{
    collections::HashMap,
    convert::TryFrom,
    ffi::CString,
    io,
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
};
use thiserror::Error;

pub use cgroup_skb::{CgroupSkb, CgroupSkbAttachType, CgroupSkbLinkId};
pub use extension::{Extension, ExtensionError, ExtensionLinkId};
pub use fentry::{FEntry, FEntryLinkId};
pub use fexit::{FExit, FExitLinkId};
pub use kprobe::{KProbe, KProbeError, KProbeLinkId};
pub use lirc_mode2::{LircLinkId, LircMode2};
pub use lsm::{Lsm, LsmLinkId};
use perf_attach::*;
pub use perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy};
pub use probe::ProbeKind;
pub use raw_trace_point::{RawTracePoint, RawTracePointLinkId};
pub use sk_msg::{SkMsg, SkMsgLinkId};
pub use sk_skb::{SkSkb, SkSkbKind, SkSkbLinkId};
pub use sock_ops::{SockOps, SockOpsLinkId};
pub use socket_filter::{SocketFilter, SocketFilterError, SocketFilterLinkId};
pub use tc::{SchedClassifier, SchedClassifierLinkId, TcAttachType, TcError};
pub use tp_btf::{BtfTracePoint, BtfTracePointLinkId};
pub use trace_point::{TracePoint, TracePointError, TracePointLinkId};
pub use uprobe::{UProbe, UProbeError, UProbeLinkId};
pub use xdp::{Xdp, XdpError, XdpFlags};

use crate::{
    generated::{bpf_attach_type, bpf_prog_info, bpf_prog_type},
    maps::MapError,
    obj::{self, btf::BtfError, Function, KernelVersion},
    sys::{
        bpf_get_object, bpf_load_program, bpf_obj_get_info_by_fd, bpf_pin_object, bpf_prog_detach,
        bpf_prog_get_fd_by_id, bpf_prog_query, retry_with_verifier_logs, BpfLoadProgramAttrs,
    },
    util::VerifierLog,
};

/// Error type returned when working with programs.
#[derive(Debug, Error)]
pub enum ProgramError {
    /// The program is already loaded.
    #[error("the program is already loaded")]
    AlreadyLoaded,

    /// The program is not loaded.
    #[error("the program is not loaded")]
    NotLoaded,

    /// The program is already detached.
    #[error("the program was already detached")]
    AlreadyDetached,

    /// The program is not attached.
    #[error("the program is not attached")]
    NotAttached,

    /// Loading the program failed.
    #[error("the BPF_PROG_LOAD syscall failed. Verifier output: {verifier_log}")]
    LoadError {
        /// The [`io::Error`] returned by the `BPF_PROG_LOAD` syscall.
        #[source]
        io_error: io::Error,
        /// The error log produced by the kernel verifier.
        verifier_log: String,
    },

    /// A syscall failed.
    #[error("`{call}` failed")]
    SyscallError {
        /// The name of the syscall which failed.
        call: String,
        /// The [`io::Error`] returned by the syscall.
        #[source]
        io_error: io::Error,
    },

    /// The network interface does not exist.
    #[error("unknown network interface {name}")]
    UnknownInterface {
        /// interface name
        name: String,
    },

    /// The program is not of the expected type.
    #[error("unexpected program type")]
    UnexpectedProgramType,

    /// Invalid pin path
    #[error("invalid pin path `{error}`")]
    InvalidPinPath {
        /// the error message
        error: String,
    },

    /// A map error occurred while loading or attaching a program.
    #[error(transparent)]
    MapError(#[from] MapError),

    /// An error occurred while working with a [`KProbe`].
    #[error(transparent)]
    KProbeError(#[from] KProbeError),

    /// An error occurred while working with an [`UProbe`].
    #[error(transparent)]
    UProbeError(#[from] UProbeError),

    /// An error occurred while working with a [`TracePoint`].
    #[error(transparent)]
    TracePointError(#[from] TracePointError),

    /// An error occurred while working with a [`SocketFilter`].
    #[error(transparent)]
    SocketFilterError(#[from] SocketFilterError),

    /// An error occurred while working with an [`Xdp`] program.
    #[error(transparent)]
    XdpError(#[from] XdpError),

    /// An error occurred while working with a TC program.
    #[error(transparent)]
    TcError(#[from] TcError),

    /// An error occurred while working with an [`Extension`] program.
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),

    /// An error occurred while working with BTF.
    #[error(transparent)]
    Btf(#[from] BtfError),

    /// The program is not attached.
    #[error("the program name `{name}` is invalid")]
    InvalidName {
        /// program name
        name: String,
    },
}

/// Allows the Fd of a loaded [`Program`] to be retrieved
pub trait ProgramFd {
    /// Returns the [`RawFd`] of the program if it has been loaded, or `None`
    fn fd(&self) -> Option<RawFd>;
}

/// eBPF program type.
#[derive(Debug)]
pub enum Program {
    /// A [`KProbe`] program
    KProbe(KProbe),
    /// A [`UProbe`] program
    UProbe(UProbe),
    /// A [`TracePoint`] program
    TracePoint(TracePoint),
    /// A [`SocketFilter`] program
    SocketFilter(SocketFilter),
    /// A [`Xdp`] program
    Xdp(Xdp),
    /// A [`SkMsg`] program
    SkMsg(SkMsg),
    /// A [`SkSkb`] program
    SkSkb(SkSkb),
    /// A [`SockOps`] program
    SockOps(SockOps),
    /// A [`SchedClassifier`] program
    SchedClassifier(SchedClassifier),
    /// A [`CgroupSkb`] program
    CgroupSkb(CgroupSkb),
    /// A [`LircMode2`] program
    LircMode2(LircMode2),
    /// A [`PerfEvent`] program
    PerfEvent(PerfEvent),
    /// A [`RawTracePoint`] program
    RawTracePoint(RawTracePoint),
    /// A [`Lsm`] program
    Lsm(Lsm),
    /// A [`BtfTracePoint`] program
    BtfTracePoint(BtfTracePoint),
    /// A [`FEntry`] program
    FEntry(FEntry),
    /// A [`FExit`] program
    FExit(FExit),
    /// A [`Extension`] program
    Extension(Extension),
}

impl Program {
    /// Returns the low level program type.
    pub fn prog_type(&self) -> bpf_prog_type {
        use crate::generated::bpf_prog_type::*;
        match self {
            Program::KProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::UProbe(_) => BPF_PROG_TYPE_KPROBE,
            Program::TracePoint(_) => BPF_PROG_TYPE_TRACEPOINT,
            Program::SocketFilter(_) => BPF_PROG_TYPE_SOCKET_FILTER,
            Program::Xdp(_) => BPF_PROG_TYPE_XDP,
            Program::SkMsg(_) => BPF_PROG_TYPE_SK_MSG,
            Program::SkSkb(_) => BPF_PROG_TYPE_SK_SKB,
            Program::SockOps(_) => BPF_PROG_TYPE_SOCK_OPS,
            Program::SchedClassifier(_) => BPF_PROG_TYPE_SCHED_CLS,
            Program::CgroupSkb(_) => BPF_PROG_TYPE_CGROUP_SKB,
            Program::LircMode2(_) => BPF_PROG_TYPE_LIRC_MODE2,
            Program::PerfEvent(_) => BPF_PROG_TYPE_PERF_EVENT,
            Program::RawTracePoint(_) => BPF_PROG_TYPE_RAW_TRACEPOINT,
            Program::Lsm(_) => BPF_PROG_TYPE_LSM,
            Program::BtfTracePoint(_) => BPF_PROG_TYPE_TRACING,
            Program::FEntry(_) => BPF_PROG_TYPE_TRACING,
            Program::FExit(_) => BPF_PROG_TYPE_TRACING,
            Program::Extension(_) => BPF_PROG_TYPE_EXT,
        }
    }

    /// Pin the program to the provided path
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ProgramError> {
        match self {
            Program::KProbe(p) => p.data.pin(path),
            Program::UProbe(p) => p.data.pin(path),
            Program::TracePoint(p) => p.data.pin(path),
            Program::SocketFilter(p) => p.data.pin(path),
            Program::Xdp(p) => p.data.pin(path),
            Program::SkMsg(p) => p.data.pin(path),
            Program::SkSkb(p) => p.data.pin(path),
            Program::SockOps(p) => p.data.pin(path),
            Program::SchedClassifier(p) => p.data.pin(path),
            Program::CgroupSkb(p) => p.data.pin(path),
            Program::LircMode2(p) => p.data.pin(path),
            Program::PerfEvent(p) => p.data.pin(path),
            Program::RawTracePoint(p) => p.data.pin(path),
            Program::Lsm(p) => p.data.pin(path),
            Program::BtfTracePoint(p) => p.data.pin(path),
            Program::FEntry(p) => p.data.pin(path),
            Program::FExit(p) => p.data.pin(path),
            Program::Extension(p) => p.data.pin(path),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProgramData<T: Link> {
    pub(crate) name: Option<String>,
    pub(crate) obj: obj::Program,
    pub(crate) fd: Option<RawFd>,
    pub(crate) links: LinkMap<T>,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) attach_btf_obj_fd: Option<u32>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<RawFd>,
    pub(crate) btf_fd: Option<RawFd>,
}

impl<T: Link> ProgramData<T> {
    pub(crate) fn new(
        name: Option<String>,
        obj: obj::Program,
        btf_fd: Option<RawFd>,
    ) -> ProgramData<T> {
        ProgramData {
            name,
            obj,
            fd: None,
            links: LinkMap::new(),
            expected_attach_type: None,
            attach_btf_obj_fd: None,
            attach_btf_id: None,
            attach_prog_fd: None,
            btf_fd,
        }
    }
}

impl<T: Link> ProgramData<T> {
    fn fd_or_err(&self) -> Result<RawFd, ProgramError> {
        self.fd.ok_or(ProgramError::NotLoaded)
    }

    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ProgramError> {
        let fd = self.fd_or_err()?;
        let path_string =
            CString::new(path.as_ref().to_string_lossy().into_owned()).map_err(|e| {
                MapError::InvalidPinPath {
                    error: e.to_string(),
                }
            })?;
        bpf_pin_object(fd, &path_string).map_err(|(_code, io_error)| {
            ProgramError::SyscallError {
                call: "BPF_OBJ_PIN".to_string(),
                io_error,
            }
        })?;
        Ok(())
    }
}

fn load_program<T: Link>(
    prog_type: bpf_prog_type,
    data: &mut ProgramData<T>,
) -> Result<(), ProgramError> {
    let ProgramData { obj, fd, .. } = data;
    if fd.is_some() {
        return Err(ProgramError::AlreadyLoaded);
    }
    let crate::obj::Program {
        function:
            Function {
                instructions,
                func_info,
                line_info,
                func_info_rec_size,
                line_info_rec_size,
                ..
            },
        license,
        kernel_version,
        ..
    } = obj;

    let target_kernel_version = match *kernel_version {
        KernelVersion::Any => {
            let (major, minor, patch) = crate::sys::kernel_version().unwrap();
            (major << 16) + (minor << 8) + patch
        }
        _ => (*kernel_version).into(),
    };

    let mut logger = VerifierLog::new();

    let prog_name = if let Some(name) = &data.name {
        let mut name = name.clone();
        if name.len() > 15 {
            name.truncate(15);
        }
        let prog_name = CString::new(name.clone())
            .map_err(|_| ProgramError::InvalidName { name: name.clone() })?;
        Some(prog_name)
    } else {
        None
    };

    let attr = BpfLoadProgramAttrs {
        name: prog_name,
        ty: prog_type,
        insns: instructions,
        license,
        kernel_version: target_kernel_version,
        expected_attach_type: data.expected_attach_type,
        prog_btf_fd: data.btf_fd,
        attach_btf_obj_fd: data.attach_btf_obj_fd,
        attach_btf_id: data.attach_btf_id,
        attach_prog_fd: data.attach_prog_fd,
        func_info_rec_size: *func_info_rec_size,
        func_info: func_info.clone(),
        line_info_rec_size: *line_info_rec_size,
        line_info: line_info.clone(),
    };
    let ret = retry_with_verifier_logs(10, &mut logger, |logger| bpf_load_program(&attr, logger));

    match ret {
        Ok(prog_fd) => {
            *fd = Some(prog_fd as RawFd);
            Ok(())
        }
        Err((_, io_error)) => {
            logger.truncate();
            return Err(ProgramError::LoadError {
                io_error,
                verifier_log: logger
                    .as_c_str()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "[none]".to_owned()),
            });
        }
    }
}

pub(crate) fn query<T: AsRawFd>(
    target_fd: T,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: &mut Option<u32>,
) -> Result<Vec<u32>, ProgramError> {
    let mut prog_ids = vec![0u32; 64];
    let mut prog_cnt = prog_ids.len() as u32;

    let mut retries = 0;

    loop {
        match bpf_prog_query(
            target_fd.as_raw_fd(),
            attach_type,
            query_flags,
            attach_flags.as_mut(),
            &mut prog_ids,
            &mut prog_cnt,
        ) {
            Ok(_) => {
                prog_ids.resize(prog_cnt as usize, 0);
                return Ok(prog_ids);
            }
            Err((_, io_error)) if retries == 0 && io_error.raw_os_error() == Some(ENOSPC) => {
                prog_ids.resize(prog_cnt as usize, 0);
                retries += 1;
            }
            Err((_, io_error)) => {
                return Err(ProgramError::SyscallError {
                    call: "bpf_prog_query".to_owned(),
                    io_error,
                });
            }
        }
    }
}

pub(crate) trait Link: std::fmt::Debug + 'static {
    type Id: std::fmt::Debug + std::hash::Hash + Eq + PartialEq;

    fn id(&self) -> Self::Id;

    fn detach(self) -> Result<(), ProgramError>;
}

#[derive(Debug)]
pub(crate) struct LinkMap<T: Link> {
    links: HashMap<T::Id, T>,
}

impl<T: Link> LinkMap<T> {
    pub(crate) fn new() -> LinkMap<T> {
        LinkMap {
            links: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, link: T) -> T::Id {
        let id = link.id();
        self.links.insert(link.id(), link);
        id
    }

    pub(crate) fn remove(&mut self, link_id: T::Id) -> Result<(), ProgramError> {
        self.links
            .remove(&link_id)
            .ok_or(ProgramError::NotAttached)?
            .detach()
    }
}

impl<T: Link> Drop for LinkMap<T> {
    fn drop(&mut self) {
        for (_, link) in self.links.drain() {
            let _ = link.detach();
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct FdLinkId(pub(crate) RawFd);

#[derive(Debug)]
pub(crate) struct FdLink {
    fd: RawFd,
}

impl FdLink {
    fn new(fd: RawFd) -> FdLink {
        FdLink { fd }
    }
}

impl Link for FdLink {
    type Id = FdLinkId;

    fn id(&self) -> Self::Id {
        FdLinkId(self.fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe { close(self.fd) };
        Ok(())
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) struct ProgAttachLinkId(RawFd, RawFd, bpf_attach_type);

#[derive(Debug)]
pub(crate) struct ProgAttachLink {
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type,
}

impl ProgAttachLink {
    pub(crate) fn new(
        prog_fd: RawFd,
        target_fd: RawFd,
        attach_type: bpf_attach_type,
    ) -> ProgAttachLink {
        ProgAttachLink {
            prog_fd,
            target_fd: unsafe { dup(target_fd) },
            attach_type,
        }
    }
}

impl Link for ProgAttachLink {
    type Id = ProgAttachLinkId;

    fn id(&self) -> Self::Id {
        ProgAttachLinkId(self.prog_fd, self.target_fd, self.attach_type)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let _ = bpf_prog_detach(self.prog_fd, self.target_fd, self.attach_type);
        unsafe { close(self.target_fd) };
        Ok(())
    }
}

macro_rules! define_link_wrapper {
    ($wrapper:ident, #[$doc:meta] $wrapper_id:ident, $base:ident, $base_id:ident) => {
        #[$doc]
        #[derive(Debug, Hash, Eq, PartialEq)]
        pub struct $wrapper_id($base_id);

        #[derive(Debug)]
        pub(crate) struct $wrapper($base);

        impl crate::programs::Link for $wrapper {
            type Id = $wrapper_id;

            fn id(&self) -> Self::Id {
                $wrapper_id(self.0.id())
            }

            fn detach(self) -> Result<(), ProgramError> {
                self.0.detach()
            }
        }

        impl From<$base> for $wrapper {
            fn from(b: $base) -> $wrapper {
                $wrapper(b)
            }
        }
    };
}

pub(crate) use define_link_wrapper;

impl ProgramFd for Program {
    fn fd(&self) -> Option<RawFd> {
        match self {
            Program::KProbe(p) => p.data.fd,
            Program::UProbe(p) => p.data.fd,
            Program::TracePoint(p) => p.data.fd,
            Program::SocketFilter(p) => p.data.fd,
            Program::Xdp(p) => p.data.fd,
            Program::SkMsg(p) => p.data.fd,
            Program::SkSkb(p) => p.data.fd,
            Program::SockOps(p) => p.data.fd,
            Program::SchedClassifier(p) => p.data.fd,
            Program::CgroupSkb(p) => p.data.fd,
            Program::LircMode2(p) => p.data.fd,
            Program::PerfEvent(p) => p.data.fd,
            Program::RawTracePoint(p) => p.data.fd,
            Program::Lsm(p) => p.data.fd,
            Program::BtfTracePoint(p) => p.data.fd,
            Program::FEntry(p) => p.data.fd,
            Program::FExit(p) => p.data.fd,
            Program::Extension(p) => p.data.fd,
        }
    }
}

impl<'a, P: ProgramFd> ProgramFd for &'a P {
    fn fd(&self) -> Option<RawFd> {
        (*self).fd()
    }
}

macro_rules! impl_program_fd {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            impl ProgramFd for $struct_name {
                fn fd(&self) -> Option<RawFd> {
                    self.data.fd
                }
            }

            impl ProgramFd for &mut $struct_name {
                fn fd(&self) -> Option<RawFd> {
                    self.data.fd
                }
            }
        )+
    }
}

impl_program_fd!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SchedClassifier,
    CgroupSkb,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
);

macro_rules! impl_try_from_program {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl<'a> TryFrom<&'a Program> for &'a $ty {
                type Error = ProgramError;

                fn try_from(program: &'a Program) -> Result<&'a $ty, ProgramError> {
                    match program {
                        Program::$ty(p) => Ok(p),
                        _ => Err(ProgramError::UnexpectedProgramType),
                    }
                }
            }

            impl<'a> TryFrom<&'a mut Program> for &'a mut $ty {
                type Error = ProgramError;

                fn try_from(program: &'a mut Program) -> Result<&'a mut $ty, ProgramError> {
                    match program {
                        Program::$ty(p) => Ok(p),
                        _ => Err(ProgramError::UnexpectedProgramType),
                    }
                }
            }
        )+
    }
}

impl_try_from_program!(
    KProbe,
    UProbe,
    TracePoint,
    SocketFilter,
    Xdp,
    SkMsg,
    SkSkb,
    SockOps,
    SchedClassifier,
    CgroupSkb,
    LircMode2,
    PerfEvent,
    Lsm,
    RawTracePoint,
    BtfTracePoint,
    FEntry,
    FExit,
    Extension,
);

/// Provides information about a loaded program, like name, id and statistics
pub struct ProgramInfo(bpf_prog_info);

impl ProgramInfo {
    /// The name of the program as was provided when it was load. This is limited to 16 bytes
    pub fn name(&self) -> &[u8] {
        let length = self
            .0
            .name
            .iter()
            .rposition(|ch| *ch != 0)
            .map(|pos| pos + 1)
            .unwrap_or(0);

        // The name field is defined as [std::os::raw::c_char; 16]. c_char may be signed or
        // unsigned depending on the platform; that's why we're using from_raw_parts here
        unsafe { std::slice::from_raw_parts(self.0.name.as_ptr() as *const _, length) }
    }

    /// The name of the program as a &str. If the name was not valid unicode, None is returned
    pub fn name_as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.name()).ok()
    }

    /// The program id for this program. Each program has a unique id.
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// Returns the fd associated with the program.
    ///
    /// The returned fd must be closed when no longer needed.
    pub fn fd(&self) -> Result<RawFd, ProgramError> {
        let fd =
            bpf_prog_get_fd_by_id(self.0.id).map_err(|io_error| ProgramError::SyscallError {
                call: "bpf_prog_get_fd_by_id".to_owned(),
                io_error,
            })?;
        Ok(fd as RawFd)
    }

    /// Loads a program from a pinned path in bpffs.
    pub fn from_pinned<P: AsRef<Path>>(path: P) -> Result<ProgramInfo, ProgramError> {
        let path_string = match CString::new(path.as_ref().to_str().unwrap()) {
            Ok(s) => s,
            Err(e) => {
                return Err(ProgramError::InvalidPinPath {
                    error: e.to_string(),
                })
            }
        };
        let fd =
            bpf_get_object(&path_string).map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_obj_get".to_owned(),
                io_error,
            })? as RawFd;

        let info = bpf_obj_get_info_by_fd(fd).map_err(|io_error| ProgramError::SyscallError {
            call: "bpf_obj_get_info_by_fd".to_owned(),
            io_error,
        })?;

        unsafe {
            libc::close(fd);
        }

        Ok(ProgramInfo(info))
    }
}
