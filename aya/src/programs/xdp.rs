use bitflags;
use libc::if_nametoindex;
use std::{
    collections::hash_map::DefaultHasher,
    ffi::CString,
    hash::{Hash, Hasher},
    io,
    os::unix::io::RawFd,
};
use thiserror::Error;

use crate::{
    generated::{
        bpf_attach_type::{self, BPF_XDP},
        bpf_prog_type::BPF_PROG_TYPE_XDP,
        XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_REPLACE, XDP_FLAGS_SKB_MODE,
        XDP_FLAGS_UPDATE_IF_NOEXIST,
    },
    programs::{load_program, FdLink, Link, ProgramData, ProgramError},
    sys::{bpf_link_create, kernel_version, netlink_set_xdp_fd},
};

/// The type returned when attaching an [`Xdp`] program fails on kernels `< 5.9`.
#[derive(Debug, Error)]
pub enum XdpError {
    /// netlink error while attaching XDP program
    #[error("netlink error while attaching XDP program")]
    NetlinkError {
        /// the [`io::Error`] from the netlink call
        #[source]
        io_error: io::Error,
    },
}

bitflags! {
    /// Flags passed to [`Xdp::attach()`].
    #[derive(Default)]
    pub struct XdpFlags: u32 {
        /// Skb mode.
        const SKB_MODE = XDP_FLAGS_SKB_MODE;
        /// Driver mode.
        const DRV_MODE = XDP_FLAGS_DRV_MODE;
        /// Hardware mode.
        const HW_MODE = XDP_FLAGS_HW_MODE;
        /// Replace a previously attached XDP program.
        const REPLACE = XDP_FLAGS_REPLACE;
        /// Only attach if there isn't another XDP program already attached.
        const UPDATE_IF_NOEXIST = XDP_FLAGS_UPDATE_IF_NOEXIST;
    }
}

/// An XDP program.
///
/// eXpress Data Path (XDP) programs can be attached to the very early stages of network
/// processing, where they can apply custom packet processing logic.  When supported by the
/// underlying network driver, XDP programs can execute directly on network cards, greatly
/// reducing CPU load.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.8.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::{Xdp, XdpFlags}};
/// use std::convert::TryInto;
///
/// let program: &mut Xdp = bpf.program_mut("intercept_packets").unwrap().try_into()?;
/// program.attach("eth0", XdpFlags::default())?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_XDP")]
pub struct Xdp {
    pub(crate) data: ProgramData<XdpLink>,
}

impl Xdp {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(bpf_attach_type::BPF_XDP);
        load_program(BPF_PROG_TYPE_XDP, &mut self.data)
    }

    /// Attaches the program to the given `interface`.
    ///
    /// The returned value can be used to detach, see [Xdp::detach].
    ///
    /// # Errors
    ///
    /// If the given `interface` does not exist
    /// [`ProgramError::UnknownInterface`] is returned.
    ///
    /// When attaching fails, [`ProgramError::SyscallError`] is returned for
    /// kernels `>= 5.9.0`, and instead
    /// [`XdpError::NetlinkError`] is returned for older
    /// kernels.
    pub fn attach(&mut self, interface: &str, flags: XdpFlags) -> Result<XdpLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let c_interface = CString::new(interface).unwrap();
        let if_index = unsafe { if_nametoindex(c_interface.as_ptr()) } as RawFd;
        if if_index == 0 {
            return Err(ProgramError::UnknownInterface {
                name: interface.to_string(),
            });
        }

        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 9, 0) {
            let link_fd = bpf_link_create(prog_fd, if_index, BPF_XDP, None, flags.bits).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create".to_owned(),
                    io_error,
                },
            )? as RawFd;
            Ok(self
                .data
                .links
                .insert(XdpLink::FdLink(FdLink::new(link_fd))))
        } else {
            unsafe { netlink_set_xdp_fd(if_index, prog_fd, None, flags.bits) }
                .map_err(|io_error| XdpError::NetlinkError { io_error })?;

            Ok(self.data.links.insert(XdpLink::NlLink(NlLink {
                if_index,
                prog_fd,
                flags,
            })))
        }
    }

    /// Detaches the program.
    ///
    /// See [Xdp::attach].
    pub fn detach(&mut self, link_id: XdpLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

#[derive(Debug)]
pub(crate) struct NlLink {
    if_index: i32,
    prog_fd: RawFd,
    flags: XdpFlags,
}

impl Link for NlLink {
    type Id = (i32, RawFd);

    fn id(&self) -> Self::Id {
        (self.if_index, self.prog_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        let k_ver = kernel_version().unwrap();
        let flags = if k_ver >= (5, 7, 0) {
            self.flags.bits | XDP_FLAGS_REPLACE
        } else {
            self.flags.bits
        };
        let _ = unsafe { netlink_set_xdp_fd(self.if_index, -1, Some(self.prog_fd), flags) };
        Ok(())
    }
}

/// The type returned by [Xdp::attach]. Can be passed to [Xdp::detach].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct XdpLinkId(u64);

#[derive(Debug)]
pub(crate) enum XdpLink {
    FdLink(FdLink),
    NlLink(NlLink),
}

impl Link for XdpLink {
    type Id = XdpLinkId;

    fn id(&self) -> Self::Id {
        let mut s = DefaultHasher::new();
        match self {
            XdpLink::FdLink(link) => link.id().hash(&mut s),
            XdpLink::NlLink(link) => link.id().hash(&mut s),
        }
        XdpLinkId(s.finish())
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            XdpLink::FdLink(link) => link.detach(),
            XdpLink::NlLink(link) => link.detach(),
        }
    }
}
