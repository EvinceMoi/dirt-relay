use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};
use clap::{App, Arg};

struct Endpoint {
    addr: SocketAddr,
    ts: u64,
}

fn timestamp() -> u64 {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    return since_epoch.as_secs();
}

fn main() {
    let opts = App::new("dirt telemetry relay")
        .version("1.0")
        .author("evin")
        .arg(Arg::with_name("source")
            .short("s").long("source").value_name("SOURCE")
            .help("source ip")
            .takes_value(true).default_value("127.0.0.1"))
        .arg(Arg::with_name("port")
            .short("p").long("port").value_name("PORT")
            .help("bind port")
            .takes_value(true).default_value("31000"))
        .get_matches();
    
    let port = opts.value_of("port").unwrap();
    let source = opts.value_of("source").unwrap();
    
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();

    let mut subs: HashMap<String, Endpoint> = HashMap::new();

    loop {
        let mut buf = [0; 576];
        let (amt, addr) = match socket.recv_from(&mut buf) {
            Ok((amt, addr)) => (amt, addr),
            Err(err) => {
                println!("recv_from error: {}", err);
                continue;
            }
        };

        let buf = &mut buf[..amt];

        let ip = addr.ip().to_string();
        if ip.ne(source) || amt == 1 {
            let now = timestamp();
            let src_addr = addr.to_string();
            if subs.contains_key(&src_addr) {
                let endp = subs.get_mut(&src_addr).unwrap();
                endp.ts = now;
            } else {
                let endp = Endpoint {
                    addr: addr,
                    ts: now,
                };
                subs.insert(src_addr, endp);
                println!("new connection from: {}", addr);
            }
            continue;
        }

        // broadcast
        let now = timestamp();
        subs.retain(|_ , endp| {
            let interval = now - endp.ts;
            interval < 10
        });

        for endp in subs.values() {
            socket.send_to(buf, endp.addr).unwrap_or_else(|err| {
                println!("send error: {}", err);
                0
            });
        }
    }
}
