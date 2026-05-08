# 🧱 Dockerwall

**Zero-trust outbound firewalling for Docker containers, powered by transparent DNS inspection.**

Dockerwall is a security daemon that tightly controls outbound traffic from your Docker containers. Instead of manually maintaining brittle lists of IP addresses or configuring complex HTTP proxies, Dockerwall lets you specify **allowed domains**. It transparently intercepts container DNS queries, dynamically adds resolved IP addresses to an allowed `ipset`, and drops all other outbound traffic at the network level.

If your container gets compromised, the attacker cannot exfiltrate data to unauthorized servers, download external payloads, or pivot to unapproved external infrastructure.

## 🛡️ Why Dockerwall? Emphasis on Security

In modern microservice architectures, containers often have unrestricted outbound internet access by default. This is a massive security risk. Traditional solutions fall short:
- **Static IP Rules:** IP addresses for services (like AWS, GitHub, or third-party APIs) change constantly. Static rules break production.
- **HTTP Proxies (Squid/Envoy):** Require modifying the container application to use proxy environments (`HTTP_PROXY`), and they don't cover non-HTTP traffic.

**Dockerwall's approach:**
1. **Default-Deny:** As soon as a Dockerwall network is created, *all outbound traffic* from that subnet is dropped.
2. **Transparent DNS Inspection:** Dockerwall runs a local DNS proxy. Container DNS queries are seamlessly rerouted via `iptables` DNAT rules to the daemon.
3. **Dynamic Network Access:** When a container requests an allowed domain (e.g., `api.github.com`), Dockerwall resolves it, instantly injects the resulting IP addresses into the container's `ipset`, and allows the traffic through.
4. **Protocol Agnostic:** Because Dockerwall operates at the network layer (`iptables`/`ipset`), it protects *all* traffic (TCP/UDP), not just HTTP.

## 🚀 Quick Start Example

Here is a full example of locking down a container so it can *only* communicate with `example.com`.

### 1. Start the Daemon
Start the Dockerwall daemon in the background. It will listen for IPC commands and manage the local DNS proxy.
```bash
sudo dockerwall daemon &
```

### 2. Prepare a Secure Network
Ask Dockerwall to create a secure Docker network named `secure-net` and restrict it strictly to `*.example.com`.
```bash
sudo dockerwall prepare-network secure-net "*.example.com"
```
*(Under the hood, Dockerwall creates the bridge network, establishes the iptables DROP/ACCEPT rules, creates the ipset, and sets up transparent DNS rerouting).*

### 3. Run Your Containers
Attach any unmodified container to the network. It will transparently be secured.

**Allowed Traffic:**
```bash
docker run --rm --network secure-net curlimages/curl:latest -sS --max-time 5 http://example.com
# ✅ Success! The DNS was inspected and the IP was dynamically allowed.
```

**Blocked Traffic:**
```bash
docker run --rm --network secure-net curlimages/curl:latest -sS --max-time 5 http://google.com
# ❌ Blocked! The connection will time out because it's dropped at the network layer.
```

## ⚙️ Architecture & Features

- **Blazing Fast `ipset`:** Dockerwall uses batched `ipset restore` commands to rapidly inject allowed IP addresses without spawning excessive subprocesses or blocking DNS resolution.
- **Asynchronous & Non-Blocking:** The transparent DNS proxy is built on a multi-threaded `tokio` async runtime, ensuring maximum throughput and immunity to network-level Denial-of-Service (DoS) attacks via delayed upstream resolvers.
- **Zero Container Modification:** You do not need to pass custom `--dns` flags, modify `/etc/resolv.conf`, or configure HTTP proxies. Everything is enforced invisibly via gateway iptables rules.

## 🛠️ Installation & Building

Make sure you have Rust installed, then compile Dockerwall from source:

```bash
cargo build --release
sudo cp target/release/dockerwall /usr/local/bin/
```

*Note: Dockerwall requires root privileges to run, as it manages `iptables`, `ipset`, and creates Docker networks.*
