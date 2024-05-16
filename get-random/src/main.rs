use std::fs;
use std::path::PathBuf;

use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use get_random_common::Event;
use log::{info, warn, debug};
use tokio::signal;
use bytes::BytesMut;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/get-random"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/get-random"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = bpf.program_mut("get_random").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_getrandom")?;

    let cpus = online_cpus()?;
    let num_cpu = cpus.len();
    let mut events: AsyncPerfEventArray<_> = bpf.take_map("EVENTS").unwrap().try_into()?;

    // Spawn tasks for each CPU
    for cpu in cpus{
        let mut buf = events.open(cpu,None)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpu)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();
            
            loop{
              // Read events from the buffer
              let events = buf.read_events(&mut buffers).await.unwrap();
              for buf in buffers.iter().take(events.read) {
                  let event = unsafe { (buf.as_ptr() as *const Event).read_unaligned() };
                  let (process_name, ppid, _uid) = read_process_status(event.pid).unwrap_or_default();
                  
                  if process_name != "code" && process_name != "Compositor" && process_name != "Chrome_IOThread"{
                    if process_name == "openssl"
                    {
                        info!("sudo process name: {:?} pid: {:?} ppid: {:?}", process_name, event.pid, ppid);
                    }
                  }
                  
                }
            }

            });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}


// Read process status from /proc/<pid>/status
fn read_process_status(pid: u32) -> Option<(String, u32, u32)> {
    let status_path = PathBuf::from(format!("/proc/{}/status", pid));
    let status_content = fs::read_to_string(status_path).ok()?;

    let mut process_name = String::new();
    let mut uid = 0;
    let mut ppid = 0;

    for line in status_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "Name:" => {
                    process_name = parts[1].to_string();
                }
                "PPid:" => {
                    ppid = parts[1].parse().unwrap_or(0);
                }
                "Uid:" => {
                    uid = parts[1].parse().unwrap_or(0);
                    break;
                }
                _ => {}
            }
        }
    }

    if !process_name.is_empty() {
        Some((process_name, ppid, uid))
    } else {
        None
    }
}
