use std::os::unix::prelude::{AsRawFd, RawFd};
use thiserror::Error;

use object::Endianness;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_INET_INGRESS, bpf_prog_type::BPF_PROG_TYPE_EXT},
    obj::btf::BtfKind,
    programs::{load_program, FdLink, ProgramData, ProgramError},
    sys::{self, bpf_link_create},
    Btf,
};

use super::{define_link_wrapper, FdLinkId};

/// The type returned when loading or attaching an [`Extension`] fails
#[derive(Debug, Error)]
pub enum ExtensionError {
    /// target BPF program does not have BTF loaded to the kernel
    #[error("target BPF program does not have BTF loaded to the kernel")]
    NoBTF,
}

/// A program used to extend existing BPF programs
///
/// [`Extension`] programs can be loaded to replace a global
/// function in a program that has already been loaded.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.9
///
/// # Examples
///
/// ```no_run
/// use aya::{BpfLoader, programs::{Xdp, XdpFlags, Extension, ProgramFd}};
/// use std::convert::TryInto;
///
/// let mut bpf = BpfLoader::new().extension("extension").load_file("app.o")?;
/// let prog: &mut Xdp = bpf.program_mut("main").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("eth0", XdpFlags::default())?;
///
/// let prog_fd = prog.fd().unwrap();
/// let ext: &mut Extension = bpf.program_mut("extension").unwrap().try_into()?;
/// ext.load(prog_fd, "function_to_replace")?;
/// ext.attach()?;
/// Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_EXT")]
pub struct Extension {
    pub(crate) data: ProgramData<ExtensionLink>,
}

impl Extension {
    /// Loads the extension inside the kernel.
    ///
    /// Prepares the code included in the extension to replace the code of the function
    /// `func_name` within the eBPF program represented by the `program` file descriptor.
    /// This requires that both the [`Extension`] and `program` have had their BTF
    /// loaded into the kernel as the verifier must check that the function signatures
    /// match.
    ///
    /// The extension code will be loaded but inactive until it's attached.
    /// There are no restrictions on what functions may be replaced, so you could replace
    /// the main entry point of your program with an extension.
    pub fn load<T: AsRawFd>(&mut self, program: T, func_name: &str) -> Result<(), ProgramError> {
        let target_prog_fd = program.as_raw_fd();

        let info = sys::bpf_obj_get_info_by_fd(target_prog_fd).map_err(|io_error| {
            ProgramError::SyscallError {
                call: "bpf_obj_get_info_by_fd".to_owned(),
                io_error,
            }
        })?;

        if info.btf_id == 0 {
            return Err(ProgramError::ExtensionError(ExtensionError::NoBTF));
        }

        let btf_fd = sys::bpf_btf_get_fd_by_id(info.btf_id).map_err(|io_error| {
            ProgramError::SyscallError {
                call: "bpf_btf_get_fd_by_id".to_owned(),
                io_error,
            }
        })?;

        let mut buf = vec![0u8; 4096];
        let btf_info = match sys::btf_obj_get_info_by_fd(btf_fd, &mut buf) {
            Ok(info) => {
                if info.btf_size > buf.len() as u32 {
                    buf.resize(info.btf_size as usize, 0u8);
                    let btf_info =
                        sys::btf_obj_get_info_by_fd(btf_fd, &mut buf).map_err(|io_error| {
                            ProgramError::SyscallError {
                                call: "bpf_obj_get_info_by_fd".to_owned(),
                                io_error,
                            }
                        })?;
                    Ok(btf_info)
                } else {
                    Ok(info)
                }
            }
            Err(io_error) => Err(ProgramError::SyscallError {
                call: "bpf_obj_get_info_by_fd".to_owned(),
                io_error,
            }),
        }?;

        let btf = Btf::parse(&buf[0..btf_info.btf_size as usize], Endianness::default())
            .map_err(ProgramError::Btf)?;

        let btf_id = btf
            .id_by_type_name_kind(func_name, BtfKind::Func)
            .map_err(ProgramError::Btf)?;

        self.data.attach_btf_obj_fd = Some(btf_fd as u32);
        self.data.attach_prog_fd = Some(target_prog_fd);
        self.data.attach_btf_id = Some(btf_id);
        load_program(BPF_PROG_TYPE_EXT, &mut self.data)
    }

    /// Attaches the extension.
    ///
    /// Attaches the extension effectively replacing the original target function.
    ///
    /// The returned value can be used to detach the extension and restore the
    /// original function, see [Extension::detach].
    pub fn attach(&mut self) -> Result<ExtensionLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let target_fd = self.data.attach_prog_fd.ok_or(ProgramError::NotLoaded)?;
        let btf_id = self.data.attach_btf_id.ok_or(ProgramError::NotLoaded)?;
        // the attach type must be set as 0, which is bpf_attach_type::BPF_CGROUP_INET_INGRESS
        let link_fd = bpf_link_create(prog_fd, target_fd, BPF_CGROUP_INET_INGRESS, Some(btf_id), 0)
            .map_err(|(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create".to_owned(),
                io_error,
            })? as RawFd;
        Ok(self.data.links.insert(ExtensionLink(FdLink::new(link_fd))))
    }

    /// Detaches the extension.
    ///
    /// Detaching restore the original code overridden by the extension program.
    /// See [Extension::attach].
    pub fn detach(&mut self, link_id: ExtensionLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

define_link_wrapper!(
    ExtensionLink,
    /// The type returned by [Extension::attach]. Can be passed to [Extension::detach].
    ExtensionLinkId,
    FdLink,
    FdLinkId
);
