use crate::{
    generated::{
        bpf_attach_type::{BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT},
        bpf_prog_type::BPF_PROG_TYPE_SK_SKB,
    },
    maps::sock::SocketMap,
    programs::{load_program, ProgAttachLink, ProgramData, ProgramError},
    sys::bpf_prog_attach,
};

use super::{define_link_wrapper, ProgAttachLinkId};

/// The kind of [`SkSkb`] program.
#[derive(Copy, Clone, Debug)]
pub enum SkSkbKind {
    /// A Stream Parser
    StreamParser,
    /// A Stream Verdict
    StreamVerdict,
}

/// A program used to intercept ingress socket buffers.
///
/// [`SkSkb`] programs are attached to [socket maps], and can be used to
/// inspect, redirect or filter incoming packet. See also [`SockMap`] and
/// [`SockHash`].
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::convert::{TryFrom, TryInto};
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress = SockMap::try_from(bpf.map_mut("INTERCEPT_INGRESS")?)?;
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_ingress)?;
/// # Ok::<(), aya::BpfError>(())
/// ```
///
/// [socket maps]: crate::maps::sock
/// [`SockMap`]: crate::maps::SockMap
/// [`SockHash`]: crate::maps::SockHash
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_SKB")]
pub struct SkSkb {
    pub(crate) data: ProgramData<SkSkbLink>,
    pub(crate) kind: SkSkbKind,
}

impl SkSkb {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_SKB, &mut self.data)
    }

    /// Attaches the program to the given socket map.
    ///
    /// The returned value can be used to detach, see [SkSkb::detach].
    pub fn attach(&mut self, map: &dyn SocketMap) -> Result<SkSkbLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let map_fd = map.fd_or_err()?;

        let attach_type = match self.kind {
            SkSkbKind::StreamParser => BPF_SK_SKB_STREAM_PARSER,
            SkSkbKind::StreamVerdict => BPF_SK_SKB_STREAM_VERDICT,
        };
        bpf_prog_attach(prog_fd, map_fd, attach_type).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach".to_owned(),
                io_error,
            }
        })?;
        Ok(self
            .data
            .links
            .insert(SkSkbLink(ProgAttachLink::new(prog_fd, map_fd, attach_type))))
    }

    /// Detaches the program.
    ///
    /// See [SkSkb::attach].
    pub fn detach(&mut self, link_id: SkSkbLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    SkSkbLink,
    /// The type returned by [SkSkb::attach]. Can be passed to [SkSkb::detach].
    SkSkbLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
