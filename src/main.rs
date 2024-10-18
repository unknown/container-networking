use std::{ffi::CString, net::Ipv4Addr, os::fd::AsRawFd};

use anyhow::{bail, Result};
use futures::TryStreamExt;
use ipnetwork::{IpNetwork, Ipv4Network};
use nftnl::{nft_expr, ChainType, Hook, MsgType, ProtoFamily};
use nix::{
    libc,
    sched::{setns, CloneFlags},
};
use rtnetlink::NetworkNamespace;
use tokio::fs::File;

const PREFIX_LENGTH: u8 = 16;

#[tokio::main]
async fn main() -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let bridge_ip = Ipv4Addr::new(172, 18, 0, 1);
    let bridge_net = IpNetwork::V4(Ipv4Network::new(bridge_ip, PREFIX_LENGTH)?);
    let bridge_idx = create_bridge(&handle, "br0", &bridge_net).await?;
    let (veth_idx, ceth_idx) = create_veth_pair(&handle, "veth0", "ceth0").await?;
    handle
        .link()
        .set(veth_idx)
        .controller(bridge_idx)
        .execute()
        .await?;

    let ns_file = create_namespace("netns0").await?;
    handle
        .link()
        .set(ceth_idx)
        .setns_by_fd(ns_file.as_raw_fd())
        .execute()
        .await?;

    let veth_ip = Ipv4Addr::new(172, 18, 0, 2);
    let veth_net = IpNetwork::V4(Ipv4Network::new(veth_ip, PREFIX_LENGTH)?);
    setup_veth_peer(&ns_file, "ceth0", &veth_net, bridge_ip).await?;

    let network_ip = Ipv4Addr::new(172, 18, 0, 0);
    let container_net = IpNetwork::V4(Ipv4Network::new(network_ip, PREFIX_LENGTH)?);
    create_nat(&container_net, "br0")?;

    Ok(())
}

/// Gets the index of a link by name.
async fn get_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        bail!("Link {} not found", name);
    }
}

/// Creates a bridge. Equivalent to:
/// ```bash
/// ip link add NAME type bridge
/// ip addr add ADDRESS/PREFIX_LENGTH dev NAME
/// ip link set NAME up
/// ```
async fn create_bridge(handle: &rtnetlink::Handle, name: &str, network: &IpNetwork) -> Result<u32> {
    handle
        .link()
        .add()
        .bridge(name.to_string())
        .execute()
        .await?;
    let index = get_index(handle, name).await?;
    handle
        .address()
        .add(index, network.ip(), network.prefix())
        .execute()
        .await?;
    handle.link().set(index).up().execute().await?;
    Ok(index)
}

/// Creates a network namespace. Equivalent to:
/// ```bash
/// ip netns add NAME
/// ```
async fn create_namespace(name: &str) -> Result<std::fs::File> {
    NetworkNamespace::add(name.to_string()).await?;
    let ns_filename = format!("/var/run/netns/{}", name);
    let tokio_ns_file = File::open(&ns_filename).await?;
    let ns_file = tokio_ns_file.into_std().await;
    Ok(ns_file)
}

/// Creates a veth pair. Equivalent to:
/// ```bash
/// ip link add NAME type veth peer name PEER_NAME
/// ip link set NAME up
/// ```
async fn create_veth_pair(
    handle: &rtnetlink::Handle,
    name: &str,
    peer_name: &str,
) -> Result<(u32, u32)> {
    handle
        .link()
        .add()
        .veth(name.to_string(), peer_name.to_string())
        .execute()
        .await?;
    let veth_idx = get_index(handle, name).await?;
    let ceth_idx = get_index(handle, peer_name).await?;
    handle.link().set(veth_idx).up().execute().await?;
    Ok((veth_idx, ceth_idx))
}

/// Sets up the veth peer in the netns namespace. Equivalent to:
/// ```bash
/// nsenter --net=NS_FILE bash
/// ip link set lo up
/// ip link set PEER_NAME up
/// ip addr add ADDRESS/PREFIX_LENGTH dev PEER_NAME
/// ip route add default via BRIDGE_ADDRESS
/// ```
async fn setup_veth_peer(
    ns_file: &std::fs::File,
    peer_name: &str,
    network: &IpNetwork,
    bridge_address: Ipv4Addr,
) -> Result<()> {
    let init_netns = File::open("/proc/1/ns/net").await?;
    setns(ns_file, CloneFlags::CLONE_NEWNET)?;
    // TODO: handle closing the connection
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    setns(init_netns, CloneFlags::CLONE_NEWNET)?;
    let lo_idx = get_index(&handle, "lo").await?;
    handle.link().set(lo_idx).up().execute().await?;
    let ceth_idx = get_index(&handle, peer_name).await?;
    handle.link().set(ceth_idx).up().execute().await?;
    handle
        .address()
        .add(ceth_idx, network.ip(), network.prefix())
        .execute()
        .await?;
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .gateway(bridge_address)
        .execute()
        .await?;
    Ok(())
}

// TODO: make this async with `tokio::spawn_blocking`
/// Creates a NAT table and chain for the given network.
fn create_nat(network: &IpNetwork, bridge_device: &str) -> Result<()> {
    let mut batch = nftnl::Batch::new();
    let table = nftnl::Table::new(&CString::new("container-nat")?, ProtoFamily::Ipv4);
    batch.add(&table, MsgType::Add);

    let mut chain = nftnl::Chain::new(&CString::new("postrouting-chain")?, &table);
    chain.set_hook(Hook::PostRouting, libc::NF_IP_PRI_NAT_SRC);
    chain.set_type(ChainType::Nat);
    batch.add(&chain, MsgType::Add);

    let mut rule = nftnl::Rule::new(&chain);
    // match on the packet's source address
    rule.add_expr(&nft_expr!(payload ipv4 saddr));
    rule.add_expr(&nft_expr!(bitwise mask network.mask(), xor 0));
    rule.add_expr(&nft_expr!(cmp == network.ip()));
    // match interface
    rule.add_expr(&nft_expr!(meta oifname));
    rule.add_expr(&nft_expr!(cmp != bridge_device));
    //apply masquerade
    rule.add_expr(&nft_expr!(masquerade));
    batch.add(&rule, MsgType::Add);

    let finalized_batch = batch.finalize();
    send_and_process(&finalized_batch)?;
    Ok(())
}

// Taken from https://github.com/mullvad/nftnl-rs/blob/main/nftnl/examples/add-rules.rs
fn send_and_process(batch: &nftnl::FinalizedBatch) -> Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    // Send all the bytes in the batch.
    socket.send_all(batch)?;

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let very_unclear_what_this_is_for = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

// Taken from https://github.com/mullvad/nftnl-rs/blob/main/nftnl/examples/add-rules.rs
fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}
