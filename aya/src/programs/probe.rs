use libc::pid_t;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    process,
};

use crate::{
    programs::{
        kprobe::KProbeError, perf_attach, perf_attach_debugfs,
        trace_point::read_sys_fs_trace_point_id, uprobe::UProbeError, ProgramData, ProgramError,
    },
    sys::{kernel_version, perf_event_open_probe, perf_event_open_trace_point},
};

use super::{perf_attach::PerfLink, Link};

/// Kind of probe program
#[derive(Debug, Copy, Clone)]
pub enum ProbeKind {
    /// Kernel probe
    KProbe,
    /// Kernel return probe
    KRetProbe,
    /// User space probe
    UProbe,
    /// User space return probe
    URetProbe,
}

impl ProbeKind {
    fn pmu(&self) -> &'static str {
        match *self {
            ProbeKind::KProbe | ProbeKind::KRetProbe => "kprobe",
            ProbeKind::UProbe | ProbeKind::URetProbe => "uprobe",
        }
    }
}

pub(crate) fn attach<T: Link + From<PerfLink>>(
    program_data: &mut ProgramData<T>,
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<T::Id, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let k_ver = kernel_version().unwrap();
    if k_ver < (4, 17, 0) {
        let (fd, event_alias) = create_as_trace_point(kind, fn_name, offset, pid)?;

        return perf_attach_debugfs(program_data, fd, kind, event_alias);
    };

    let fd = create_as_probe(kind, fn_name, offset, pid)?;

    perf_attach(program_data, fd)
}

pub(crate) fn detach_debug_fs(kind: ProbeKind, event_alias: &str) -> Result<(), ProgramError> {
    use ProbeKind::*;

    let _ = match kind {
        KProbe | KRetProbe => delete_probe_event(kind, event_alias)
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => delete_probe_event(kind, event_alias)
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    Ok(())
}

fn create_as_probe(
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<i32, ProgramError> {
    use ProbeKind::*;

    let perf_ty = match kind {
        KProbe | KRetProbe => read_sys_fs_perf_type(kind.pmu())
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => read_sys_fs_perf_type(kind.pmu())
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let ret_bit = match kind {
        KRetProbe => Some(
            read_sys_fs_perf_ret_probe(kind.pmu())
                .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        ),
        URetProbe => Some(
            read_sys_fs_perf_ret_probe(kind.pmu())
                .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
        ),
        _ => None,
    };

    let fd = perf_event_open_probe(perf_ty, ret_bit, fn_name, offset, pid).map_err(
        |(_code, io_error)| ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        },
    )? as i32;

    Ok(fd)
}

fn create_as_trace_point(
    kind: ProbeKind,
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<(i32, String), ProgramError> {
    use ProbeKind::*;

    let event_alias = match kind {
        KProbe | KRetProbe => create_probe_event(kind, name, offset)
            .map_err(|(filename, io_error)| KProbeError::FileError { filename, io_error })?,
        UProbe | URetProbe => create_probe_event(kind, name, offset)
            .map_err(|(filename, io_error)| UProbeError::FileError { filename, io_error })?,
    };

    let category = format!("{}s", kind.pmu());
    let tpid = read_sys_fs_trace_point_id(&category, &event_alias)?;
    let fd = perf_event_open_trace_point(tpid, pid).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "perf_event_open".to_owned(),
            io_error,
        }
    })? as i32;

    Ok((fd, event_alias))
}

fn create_probe_event(
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
) -> Result<String, (String, io::Error)> {
    use ProbeKind::*;

    let events_file_name = format!("/sys/kernel/debug/tracing/{}_events", kind.pmu());
    let probe_type_prefix = match kind {
        KProbe | UProbe => 'p',
        KRetProbe | URetProbe => 'r',
    };
    let event_alias = format!(
        "aya_{}_{}_{}_{:#x}",
        process::id(),
        probe_type_prefix,
        fn_name,
        offset
    );
    let offset_suffix = match kind {
        KProbe => format!("+{}", offset),
        UProbe => format!(":{:#x}", offset),
        _ => "".to_string(),
    };
    let probe = format!(
        "{}:{}s/{} {}{}\n",
        probe_type_prefix,
        kind.pmu(),
        event_alias,
        fn_name,
        offset_suffix
    );

    let mut events_file = OpenOptions::new()
        .append(true)
        .open(&events_file_name)
        .map_err(|e| (events_file_name.clone(), e))?;

    events_file
        .write_all(probe.as_bytes())
        .map_err(|e| (events_file_name.clone(), e))?;

    Ok(event_alias)
}

fn delete_probe_event(kind: ProbeKind, event_alias: &str) -> Result<(), (String, io::Error)> {
    let events_file_name = format!("/sys/kernel/debug/tracing/{}_events", kind.pmu());

    let events =
        fs::read_to_string(&events_file_name).map_err(|e| (events_file_name.clone(), e))?;

    let found = events.lines().any(|line| line.contains(event_alias));

    if found {
        let mut events_file = OpenOptions::new()
            .append(true)
            .open(&events_file_name)
            .map_err(|e| (events_file_name.to_string(), e))?;

        let rm = format!("-:{}\n", event_alias);

        events_file
            .write_all(rm.as_bytes())
            .map_err(|e| (events_file_name.to_string(), e))?;
    }

    Ok(())
}

fn read_sys_fs_perf_type(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{}/type", pmu);

    let perf_ty = fs::read_to_string(&file).map_err(|e| (file.clone(), e))?;
    let perf_ty = perf_ty
        .trim()
        .parse::<u32>()
        .map_err(|e| (file, io::Error::new(io::ErrorKind::Other, e)))?;

    Ok(perf_ty)
}

fn read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, (String, io::Error)> {
    let file = format!("/sys/bus/event_source/devices/{}/format/retprobe", pmu);

    let data = fs::read_to_string(&file).map_err(|e| (file.clone(), e))?;

    let mut parts = data.trim().splitn(2, ':').skip(1);
    let config = parts.next().ok_or_else(|| {
        (
            file.clone(),
            io::Error::new(io::ErrorKind::Other, "invalid format"),
        )
    })?;

    config
        .parse::<u32>()
        .map_err(|e| (file, io::Error::new(io::ErrorKind::Other, e)))
}
