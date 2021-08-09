use std::{net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket}, process::exit};
use clap::{App, Arg};

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
        .arg(Arg::with_name("group")
            .short("g").long("group").value_name("group")
            .help("multicast group")
            .takes_value(true).default_value("239.10.9.8"))
        .get_matches();
    
    let port = opts.value_of("port").unwrap();
    let source = opts.value_of("source").unwrap();
    let group = opts.value_of("group").unwrap();
    println!("port: {}, source: {}, group: {}", port, source, group);

    let group_addr = match group.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(err) => {
            println!("group address error: {}", err);
            exit(1);
        }
    };
    if !group_addr.is_multicast() {
        println!("group must be a valid multicast address");
        exit(1);
    }

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();
    socket.set_broadcast(true).unwrap();
    socket.set_multicast_ttl_v4(64).unwrap();
    if group_addr.is_ipv4() {
        socket.set_multicast_loop_v4(false).expect("failed to set_multicast_loop_v4(false)");
    } else {
        socket.set_multicast_loop_v6(false).expect("failed to set_multicast_loop_v6(false)");
    }

    let to_addrs = SocketAddr::new(group_addr, port.parse::<u16>().unwrap()).to_socket_addrs().unwrap();
    let to_addr = to_addrs.clone().next().unwrap();
    println!("to_addr: {}", to_addr);

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

        if amt == 1 && buf[0] == 0x2A { 
            // sub, reply multicast addr
            println!("sub from {}", addr);
            let mut remote_ip = match addr.ip() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut gaddr = match group_addr {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut data = vec![gaddr.len() as u8];
            data.append(&mut gaddr);

            data.push(remote_ip.len() as u8);
            data.append(&mut remote_ip);

            socket.send_to(data.as_ref(), addr).unwrap();
            continue;
        } else if addr.ip().to_string().eq(source) {
            // multicast
            match socket.send_to(buf, to_addr) {
                Ok(s) => s,
                Err(err) => {
                    println!("send_to {} error: {}", to_addr, err);
                    0
                }
            };
        }
    }
}
