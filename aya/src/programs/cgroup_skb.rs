use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    generated::{
        bpf_attach_type::{BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS},
        bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB,
    },
    programs::{load_program, ProgAttachLink, ProgramData, ProgramError},
    sys::{bpf_link_create, bpf_prog_attach, kernel_version},
};

use super::{FdLink, Link};

/// A program used to inspect or filter network activity for a given cgroup.
///
/// [`CgroupSkb`] programs can be used to inspect or filter network activity
/// generated on all the sockets belonging to a given [cgroup]. They can be
/// attached to both _ingress_ and _egress_.
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.10.
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
/// use aya::programs::{CgroupSkb, CgroupSkbAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSkb = bpf.program_mut("egress_filter").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupSkbAttachType::Egress)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SKB")]
pub struct CgroupSkb {
    pub(crate) data: ProgramData<CgroupSkbLink>,
    pub(crate) expected_attach_type: Option<CgroupSkbAttachType>,
}

impl CgroupSkb {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_CGROUP_SKB, &mut self.data)
    }

    /// Returns the expected attach type of the program.
    ///
    /// [`CgroupSkb`] programs can specify the expected attach type in their ELF
    /// section name, eg `cgroup_skb/ingress` or `cgroup_skb/egress`. This
    /// method returns `None` for programs defined with the generic section
    /// `cgroup/skb`.
    pub fn expected_attach_type(&self) -> &Option<CgroupSkbAttachType> {
        &self.expected_attach_type
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSkb::detach].
    pub fn attach<T: AsRawFd>(
        &mut self,
        cgroup: T,
        attach_type: CgroupSkbAttachType,
    ) -> Result<CgroupSkbLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();

        let attach_type = match attach_type {
            CgroupSkbAttachType::Ingress => BPF_CGROUP_INET_INGRESS,
            CgroupSkbAttachType::Egress => BPF_CGROUP_INET_EGRESS,
        };
        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, None, 0).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create".to_owned(),
                    io_error,
                },
            )? as RawFd;
            Ok(self
                .data
                .links
                .insert(CgroupSkbLink::Fd(FdLink::new(link_fd))))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                ProgramError::SyscallError {
                    call: "bpf_prog_attach".to_owned(),
                    io_error,
                }
            })?;

            Ok(self
                .data
                .links
                .insert(CgroupSkbLink::ProgAttach(ProgAttachLink::new(
                    prog_fd,
                    cgroup_fd,
                    attach_type,
                ))))
        }
    }

    /// Detaches the program.
    ///
    /// See [CgroupSkb::attach].
    pub fn detach(&mut self, link_id: CgroupSkbLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

/// The type returned by [CgroupSkb::attach]. Can be passed to [CgroupSkb::detach].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct CgroupSkbLinkId(u64);

#[derive(Debug)]
pub(crate) enum CgroupSkbLink {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSkbLink {
    type Id = CgroupSkbLinkId;

    fn id(&self) -> Self::Id {
        let mut s = DefaultHasher::new();
        match self {
            CgroupSkbLink::Fd(fd) => fd.id().hash(&mut s),
            CgroupSkbLink::ProgAttach(p) => p.id().hash(&mut s),
        }

        CgroupSkbLinkId(s.finish())
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSkbLink::Fd(fd) => fd.detach(),
            CgroupSkbLink::ProgAttach(p) => p.detach(),
        }
    }
}

/// Defines where to attach a [`CgroupSkb`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSkbAttachType {
    /// Attach to ingress.
    Ingress,
    /// Attach to egress.
    Egress,
}
