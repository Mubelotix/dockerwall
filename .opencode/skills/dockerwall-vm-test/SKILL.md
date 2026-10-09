---
name: dockerwall-vm-test
description: Use when debugging Dockerwall `prepare-network --runtime podman`, rootless Podman IPv6 allocation or exhaustion, or when a privileged network/firewall integration test is needed; run it in a disposable QEMU/KVM VM, not a rootless container.
---

# Dockerwall VM integration testing

Use a disposable VM for tests that exercise Dockerwall's real host networking path. `prepare-network --runtime podman` deliberately checks that it runs as host root and rejects root inside a user namespace; `podman run --privileged` under rootless Podman is not an equivalent environment.

## Test the repeated-preparation regression

The core regression is idempotency: preparing the same Podman policy repeatedly must reuse the IPv6 source address already recorded in that policy's IPv6 `OUTPUT` firewall hook. A regression previously allocated a fresh address on every call and exhausted 50 candidate addresses.

1. Confirm QEMU/KVM availability (`qemu-system-x86_64`, readable/writable `/dev/kvm`), `qemu-img`, `cloud-localds`, SSH, and enough disk space.
2. Download a supported Debian/Ubuntu cloud image from its official cloud-image directory and verify it against that directory's published checksum file.
3. Create a throwaway qcow2 overlay and cloud-init seed. Configure an SSH key for a temporary guest user with passwordless sudo. Boot with KVM, user-mode networking, and SSH forwarded only on host loopback (for example `127.0.0.1:2223`). Do not use host networking or bridge the VM into production networks.
4. Transfer a source snapshot into the guest over the forwarded SSH connection (`scp`). A 9p share may not be supported by the cloud guest kernel. Exclude `.git` and build outputs from the snapshot; include uncommitted source changes being tested.
5. In the guest install `podman`, `passt`, `iproute2`, `iptables`, `ipset`, `curl`, and build tools. Install a current stable Rust toolchain if the distribution's packaged Rust is too old, then build the copied source with `cargo build --release --locked`.
6. Confirm rootless Podman works for the guest user (`podman info --format '{{.Host.Security.Rootless}}'`). Find the guest's default-route interface. If it has no global IPv6 `/64`, add a test-only documentation prefix to that guest interface, e.g. `sudo ip -6 addr add 2001:db8:1234:5678::1/64 dev "$IFACE"`. This is only to exercise IPv6 allocation; it does not provide routed IPv6 connectivity.
7. Start the Dockerwall daemon inside the VM and wait for `/run/dockerwall.sock`. Run the built binary as guest root for every preparation:

   ```sh
   sudo "$BIN" prepare-network --runtime podman --interface "$IFACE" vm-repeat-test '*.example.com'
   ```

   Repeat this exact command at least three times, capturing each output. Assert that every `rootless Podman source IPv6:` value is identical. Record the interface's global IPv6 address count before the first preparation and after the last; a fresh test should add exactly one Dockerwall source alias, not one per preparation. Keep all state inside the disposable guest.

8. If investigating a reported exhausted host, also test a fresh policy name and inspect the guest's IPv6 `OUTPUT` rules and interface addresses. Never delete addresses or firewall rules from the real host as part of this test.

## Optional rootless traffic test

When the guest has working outbound IPv4 and a Podman version compatible with Dockerwall's generated `pasta:` arguments, run the existing `test-rootless-podman.sh` workflow in the guest or run an allowed and a blocked IPv4 request using the printed pasta network arguments. Capture `podman --version` and the precise error if it rejects those options; distro Podman versions differ. A pasta-option compatibility failure is separate from whether repeated `prepare-network` calls reuse an address. Do not claim IPv6 connectivity based only on assigning a documentation prefix.

## Evidence and cleanup

- Report the guest OS/kernel, Dockerwall build revision, Podman version, the repeated source-address values, and address-count delta.
- Distinguish real `prepare-network`/iptables execution in the VM from simulated allocator tests and from optional container traffic tests.
- Stop the VM and temporary transfer server; remove the qcow2 overlay, cloud-init seed, downloaded image, temporary SSH key, and source archive. Do not leave test keys or images in the repository.
- Keep the regression test in the repository so CI can validate address reuse without requiring host-root firewall access. Use the VM when validating the real privileged boundary.
