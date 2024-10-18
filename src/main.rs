use std::{net::Ipv4Addr, os::fd::AsRawFd};

use anyhow::{bail, Result};
use futures::TryStreamExt;
use ipnetwork::{IpNetwork, Ipv4Network};
use nix::sched::{setns, CloneFlags};
use rtnetlink::NetworkNamespace;
use tokio::fs::File;

#[tokio::main]
async fn main() -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let bridge_ip = Ipv4Addr::new(172, 18, 0, 1);
    let bridge_net = IpNetwork::V4(Ipv4Network::new(bridge_ip, 16)?);
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
    let veth_net = IpNetwork::V4(Ipv4Network::new(veth_ip, 16)?);
    setup_veth_peer(&ns_file, "ceth0", &veth_net, bridge_ip).await?;

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
    let veth_idx = get_index(handle, &name).await?;
    let ceth_idx = get_index(handle, &peer_name).await?;
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
