use std::os::unix::io::AsRawFd;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS},
    programs::{load_program, ProgAttachLink, ProgramData, ProgramError},
    sys::bpf_prog_attach,
};

use super::{define_link_wrapper, ProgAttachLinkId};

/// A program used to work with sockets.
///
/// [`SockOps`] programs can access or set socket options, connection
/// parameters, watch connection state changes and more. They are attached to
/// cgroups.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.13.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
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
/// use std::fs::File;
/// use std::convert::TryInto;
/// use aya::programs::SockOps;
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let prog: &mut SockOps = bpf.program_mut("intercept_active_sockets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(file)?;
/// # Ok::<(), Error>(())
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCK_OPS")]
pub struct SockOps {
    pub(crate) data: ProgramData<SockOpsLink>,
}

impl SockOps {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCK_OPS, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [SockOps::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<SockOpsLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();

        bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach".to_owned(),
                io_error,
            }
        })?;
        Ok(self.data.links.insert(SockOpsLink(ProgAttachLink::new(
            prog_fd,
            cgroup_fd,
            BPF_CGROUP_SOCK_OPS,
        ))))
    }

    /// Detaches the program.
    ///
    /// See [SockOps::attach].
    pub fn detach(&mut self, link_id: SockOpsLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    SockOpsLink,
    /// The type returned by [SockOps::attach]. Can be passed to [SockOps::detach].
    SockOpsLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
