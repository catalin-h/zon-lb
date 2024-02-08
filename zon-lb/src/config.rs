use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct EP {
    ip: String,
    proto: u8,
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct Group {
    id: u16,
    ep: EP,
}

#[derive(Serialize, Deserialize)]
struct NetIf {
    name: String,
    groups: Vec<Group>,
}

#[derive(Serialize, Deserialize)]
struct Backend {
    gid: u16,
    ep: EP,
}

#[derive(Serialize, Deserialize)]
struct Config {
    ifaces: NetIf,
    backends: Vec<Backend>,
}
