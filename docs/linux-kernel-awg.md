# Linux kernel AWG rollout

Linux NetBird-AWG agents can use the `amneziawg` kernel data path when the
installed module implements the NetBird per-peer transport UAPI. This applies
to routing peers and ordinary Linux peers.

The Agent does not select the module by name alone. Before login it creates a
temporary `amneziawg` link and verifies all of the following:

- the `amneziawg` link kind is available;
- the `amneziawg` generic-netlink family is version 3;
- the device advertises the per-peer transport-mode capability.

If any check fails, a Linux peer does not advertise kernel AWG support.
Management then keeps both directions symmetric:

- `prefer_awg` resolves the pair to Standard WireGuard;
- `require_awg` blocks the pair;
- non-Linux peers can continue to use the userspace AWG backend.

Linux netstack mode and `NB_WG_KERNEL_DISABLED=true` disable the kernel probe.
There is no silent Linux userspace-AWG fallback after a kernel profile has been
assigned. A setup failure withdraws the capability until the Agent reconnects
and Management computes a new symmetric mode.

## Install the kernel module

Use a disposable Linux router first. Replacing a tunnel implementation can
interrupt routing, firewall, and DNS state.

On Ubuntu, install build tools and the headers for the running kernel:

```sh
sudo apt-get update
sudo apt-get install -y build-essential "linux-headers-$(uname -r)"
git clone --branch netbird-WireGuard-awg \
  https://github.com/netbird-awg/amneziawg-linux-kernel-module.git
cd amneziawg-linux-kernel-module
./scripts/build-linux.sh W=1
sudo make -C src install
sudo depmod -a
sudo modprobe amneziawg
```

Confirm that the kernel exposes the link kind:

```sh
sudo ip link add nbawg-smoke type amneziawg
sudo ip link delete nbawg-smoke
test -d /sys/module/amneziawg
```

The link smoke test is necessary but not sufficient. The Agent's pre-login
probe also verifies generic-netlink version 3 and the per-peer capability bit.

## Build and install the Agent

The AWG release configuration includes the `hybrid_awg` build tag. For a local
build, set it explicitly:

```sh
go build -tags hybrid_awg -o bin/netibird-awg ./client
```

Stop an existing Agent and restore its network state before replacing it:

```sh
sudo netibird-awg down
sudo netibird-awg service stop
```

Install the tested binary using the normal package or service workflow for the
host. Do not run two NetBird-AWG daemons against the same interface.

The following settings must remain unset or false on a kernel-AWG router:

```text
NB_USE_NETSTACK_MODE
NB_WG_KERNEL_DISABLED
```

## Verify selection

After Management assigns the AWG profile, connect the Agent and inspect both
the interface and local status. The default interface name is `wt0`.

```sh
sudo netibird-awg up
ip -details link show dev wt0
netibird-awg status --json | jq '.usesKernelInterface'
```

The link must be of type `amneziawg`, and `usesKernelInterface` must be `true`.
Also verify traffic in both directions with the workload used by the router.
For a routing peer, include forwarded TCP and UDP traffic, multiple peers, and
the expected MTU.

Peer eligibility is symmetric:

- a Linux peer needs the compatible kernel module to participate in AWG;
- macOS, Windows, FreeBSD, Android, and iOS peers use userspace AWG;
- if either side is ineligible under `prefer_awg`, both sides use Standard;
- if either side is ineligible under `require_awg`, the pair is blocked.

## Roll back

Change the account tunnel policy to Standard before removing the module. Wait
for peers to receive the Standard decision, then stop the Agent and remove the
interface:

```sh
sudo netibird-awg down
sudo netibird-awg service stop
sudo modprobe -r amneziawg
```

Do not unload the module while `wt0` or another `amneziawg` link is active.
