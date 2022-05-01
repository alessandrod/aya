use libc::close;
use std::os::unix::io::RawFd;

use crate::{
    programs::{probe::detach_debug_fs, ProbeKind},
    sys::perf_event_ioctl,
    PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF,
};

use super::{Link, ProgramData, ProgramError};

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PerfLinkId(RawFd);

#[derive(Debug)]
pub(crate) struct PerfLink {
    perf_fd: RawFd,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
}

impl Link for PerfLink {
    type Id = PerfLinkId;

    fn id(&self) -> Self::Id {
        PerfLinkId(self.perf_fd)
    }

    fn detach(mut self) -> Result<(), ProgramError> {
        let _ = perf_event_ioctl(self.perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        unsafe { close(self.perf_fd) };

        if let Some(probe_kind) = self.probe_kind.take() {
            if let Some(event_alias) = self.event_alias.take() {
                let _ = detach_debug_fs(probe_kind, &event_alias);
            }
        }

        Ok(())
    }
}

pub(crate) fn perf_attach<T: Link + From<PerfLink>>(
    data: &mut ProgramData<T>,
    fd: RawFd,
) -> Result<T::Id, ProgramError> {
    perf_attach_either(data, fd, None, None)
}

pub(crate) fn perf_attach_debugfs<T: Link + From<PerfLink>>(
    data: &mut ProgramData<T>,
    fd: RawFd,
    probe_kind: ProbeKind,
    event_alias: String,
) -> Result<T::Id, ProgramError> {
    perf_attach_either(data, fd, Some(probe_kind), Some(event_alias))
}

fn perf_attach_either<T: Link + From<PerfLink>>(
    data: &mut ProgramData<T>,
    fd: RawFd,
    probe_kind: Option<ProbeKind>,
    event_alias: Option<String>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = data.fd_or_err()?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd).map_err(|(_, io_error)| {
        ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF".to_owned(),
            io_error,
        }
    })?;
    perf_event_ioctl(fd, PERF_EVENT_IOC_ENABLE, 0).map_err(|(_, io_error)| {
        ProgramError::SyscallError {
            call: "PERF_EVENT_IOC_ENABLE".to_owned(),
            io_error,
        }
    })?;

    Ok(data.links.insert(
        PerfLink {
            perf_fd: fd,
            probe_kind,
            event_alias,
        }
        .into(),
    ))
}
