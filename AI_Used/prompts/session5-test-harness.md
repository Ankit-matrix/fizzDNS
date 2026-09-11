# Session 5 prompts — running everything on real hardware

Chat: `[FILL IN]`
Date: `[FILL IN]`

---

### Prompt 1

> i need to test everything and get the output , just tell me the code to
> do so on my pc

**What came back:** `collect_results.sh` — one script running everything
into `results/ALL.txt`, written and executed end-to-end in the sandbox
before being handed over, so it was tested rather than theoretical.

```sh
cd ~/dns_ax
chmod +x collect_results.sh

./collect_results.sh          # tiers 1-3: no NIC needed
./collect_results.sh eth0     # + tier 4 on a real interface
```

| Tier | Produces | Needs |
|---|---|---|
| 1 | Build warnings, BPF verifier | root |
| 2 | 227 unit checks, TSan | nothing |
| 3 | 28 offline + 36 adversarial, resolver counters, Bloom A/B table, scaling curve | port 53 |
| 4 | Zero-copy mode line, per-queue RX split, guard rail | root + NIC |

**Two bugs hit while writing it**, both reported rather than quietly fixed:

- `$SUDO VAR=x ./cmd` breaks silently when `$SUDO` is empty — shell
  assignments are recognised before variable expansion, so with no sudo the
  shell tries to execute `DNS_ROOT_HINTS=127.0.0.21` as a command. The
  adversarial tier failed with "no response" and looked like a server
  problem. Fixed with `env`.
- `pkill -f evil_hierarchy` matches the script's own command line and kills
  the shell running it. Fixed to `pkill -f "[e]vil_hierarchy"`.

**What the script cannot do:** transport throughput and latency need a load
generator with both arms on the same link, run manually:

```sh
gcc -O2 -Wall -o loadgen loadgen.c

# AF_XDP arm
sudo ./af_xdp_user_stub -d eth0 --filename ./af_xdp_kern.o --queues 2 -w 4
./loadgen -s <SERVER_IP> -p 53 -d 30 -c 4 | tee results/xdp_load.txt

# UDP arm — same IP, same link, same worker count
sudo ./server_stub -p 53 -w 4
./loadgen -s <SERVER_IP> -p 53 -d 30 -c 4 | tee results/udp_load.txt
```

Use the `_stub` binaries — the real backend blocks on upstream DNS for up
to 2 s, so otherwise you measure the resolver, not the transport.

**The open question it flagged:** every figure in the report was
single-core, and the filter's justification is that a miss skips a
contended mutex — untested. If the bloom/no-bloom gap widens with thread
count, the contention explanation holds and can be stated; if it stays
flat, the filter still helps but for a different reason and the report must
be corrected. Either result is worth reporting; guessing is not. The
shipped `sample_results.txt` is a 1-core container's output, so its
multi-thread rows are convoy artifacts — use it to check output formatting,
not as data.
