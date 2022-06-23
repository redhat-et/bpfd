// SPDX-License-Identifier: (MIT OR Apache-2.0)
// Copyright Authors of bpfd

use std::{
    fs::{create_dir_all, File},
    io::{BufRead, BufReader},
};

use anyhow::{bail, Context};
use aya::include_bytes_aligned;
use bpfd::server::{config_from_file, serve};
use log::debug;
use nix::{
    libc::RLIM_INFINITY,
    mount::{mount, MsFlags},
    sys::resource::{setrlimit, Resource},
};

use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const BPFFS: &str = "/var/run/bpfd/fs";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .add_filter_ignore("h2".to_string())
            .add_filter_ignore("rustls".to_string())
            .add_filter_ignore("hyper".to_string())
            .add_filter_ignore("aya".to_string())
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;
    let dispatcher_bytes =
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_dispatcher.bpf.o"));

    setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY)
        .context("unable to set rlimit")?;

    create_dir_all(BPFFS).context("unable to create mountpoint")?;

    if !is_bpffs_mounted()? {
        debug!("Creating bpffs at /var/run/bpfd/fs");
        let flags =
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RELATIME;
        mount::<str, str, str, str>(None, BPFFS, Some("bpf"), flags, None)
            .context("unable to mount bpffs")?;
    }

    let config = config_from_file("/etc/bpfd.toml");
    serve(config, dispatcher_bytes).await?;
    Ok(())
}

fn is_bpffs_mounted() -> Result<bool, anyhow::Error> {
    let file = File::open("/proc/mounts").context("Failed to open /proc/mounts")?;
    let reader = BufReader::new(file);
    for l in reader.lines() {
        match l {
            Ok(line) => {
                let parts: Vec<&str> = line.split(' ').collect();
                if parts.len() != 6 {
                    bail!("expected 6 parts in proc mount")
                }
                if parts[0] == "none" && parts[1].contains("bpfd") && parts[2] == "bpf" {
                    return Ok(true);
                }
            }
            Err(e) => bail!("problem reading lines {}", e),
        }
    }
    Ok(false)
}
