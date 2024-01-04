use aya::{programs::Lsm, Btf};
use aya::{include_bytes_aligned, Bpf, maps::perf::AsyncPerfEventArray, util::online_cpus};
use aya_log::BpfLogger;
use bytes::BytesMut;

use log::{info, warn, debug};
use tokio::signal;
use lsm_rs_common::{EventType, Event};
use serde_json::{json, to_string_pretty};



fn serialize_exec_json(_etype: EventType, path: &str, uid: u32, gid: u32, dev: u32, inode: u64) -> String {
    let tpath = path.to_string();
    let trimmed_path = tpath.trim_matches(char::from(0));

    let user = users::get_user_by_uid(uid).unwrap();
    let group = users::get_group_by_gid(gid).unwrap();
    let event = json!(
    {
        "LsmEvent": {
            "Meta": {
                "Type": "Exec",
                "SecurityHook": "security_bprm_check"
            },
            "Data": {
                "Path": trimmed_path,
                "User": user.name().to_string_lossy(),
                "Group": group.name().to_string_lossy(),
                "Device": dev.to_string(),
                "Inode": inode.to_string()
            }
        }
    });

    to_string_pretty(&event).unwrap()
}

fn load_programs(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("bprm_check_security").unwrap().try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    let exec_events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap()).unwrap();
    print_type_of(&exec_events);
    Ok(())
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn load_perf_array(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let _array = AsyncPerfEventArray::try_from(bpf.map_mut("EXEC_EVENTS").unwrap()).unwrap(); 
    Ok(())
}

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
        "../../target/bpfel-unknown-none/debug/lsm-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lsm-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    load_programs(&mut bpf)?;
    let mut exec_events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Process events from the perf buffer.
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();

    for cpu in cpus {
        let mut buf = exec_events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10204))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;
                    let data = unsafe { ptr.read_unaligned() };     

                    let etype: EventType = data.etype;
                    let path = unsafe {
                        core::str::from_utf8_unchecked(&data.path)
                    };
                    println!("{},", serialize_exec_json(etype, path, data.uid, data.gid, data.dev, data.inode));

                    //println!("Event received: {:?}, {}, {}, {}", etype, path, data.dev, data.inode);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
