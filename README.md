# HW-2 AES-128 RTL (Baseline)

This repository contains a minimal, stable **AES-128 encryption** RTL implementation and a reproducible validation setup against **OpenSSL** (reference implementation).
The baseline AES core is extended with fault-detection and side-channel countermeasures for research and evaluation.

---

## Repository Layout

```
root/
├─ rtl/
│  ├─ aes_top.v              # thin wrapper / top-level module
│  ├─ aes_core.v             # iterative AES-128 encrypt core (1 round per cycle)
│  ├─ aes_round.v            # SubBytes + ShiftRows + (MixColumns) + AddRoundKey
│  ├─ aes_key_expand_128.v   # AES-128 key schedule (one-step expansion)
│  └─ aes_sbox.v             # AES forward S-box (LUT)
├─ tb/
│  └─ tb_aes128.sv           # testbench: reads vectors.txt and compares outputs
│  └─ tb_fault.sv            # testbench: run fault attack and verify the defense
│  └─ tb_power.sv            # testbench: observe switching activity / power proxy
├─ scripts/
│  └─ gen_vectors.py         # generates OpenSSL reference vectors (ECB, 1-block, no pad)
├─ run.sh                    # one-command: generate vectors, compile, simulate
├─ run_fault.sh              # based on run.sh, but add verification for fault defense
├─ run_power.sh              # still based on run.sh, but add verification for power-side defense
├─ vectors.txt               # generated test vectors (key pt ct_ref) [will be ignored]
└─ .gitignore
```

---

## Design Overview

### AES Architecture

* **AES-128 encryption only** (no decryption).
* **Iterative datapath**: computes **one AES round per cycle**.
* Round 0 (`AddRoundKey`) is applied on `start`.
* Rounds 1..10 run sequentially; round 10 is the **final round** (no MixColumns).

### Key Schedule

* AES-128 key schedule is implemented as a one-step expansion:

  * `rk_next = KeyExpand128(rk_prev, rcon(round))`
* The core generates round keys on-the-fly (no pre-expanded storage).

### Top-Level Handshake (aes_top / aes_core)

* Inputs: `start`, `key[127:0]`, `plaintext[127:0]`
* Outputs: `busy`, `done` (1-cycle pulse), `ciphertext[127:0]`
* `start` is accepted when `busy==0`.
* `done` asserts for one cycle when ciphertext is valid.

---

## Validation (RTL vs OpenSSL)

### Prerequisites

* Python 3
* OpenSSL (supports `enc -aes-128-ecb`)
* Icarus Verilog (`iverilog`, `vvp`)

### Run

From repo root:

```bash
./run.sh
```

You can optionally generate more vectors:

```bash
./run.sh 200
```

### What `run.sh` does

1. Calls `scripts/gen_vectors.py` to generate `vectors.txt`:

   * Each line: `KEY_HEX(32) PLAINTEXT_HEX(32) CIPHERTEXT_HEX(32)`
   * Ciphertext is computed by OpenSSL: AES-128-ECB, **no padding**, **no salt**
2. Compiles RTL + testbench with `iverilog`
3. Runs simulation with `vvp` and checks all vectors

A successful run prints:

```
Total: N  Pass: N  Fail: 0
RESULT: PASS
```

---

### Notes

* Baseline correctness is required before adding fault/power countermeasures.
* `vectors.txt` and build outputs (e.g., `sim.out`, `*.vcd`) are typically ignored by `.gitignore`.

---

## Fault Defense: Temporal + Spatial Redundancy

### Summary

Fault detection uses **both temporal and spatial redundancy** in one design:

* **Spatial redundancy (dual-core lockstep)**  
  Two AES cores run in parallel with the same `(key, plaintext)` and the same `step_en`.  
  Each cycle, the two internal states are compared (`core_A_state` vs `core_B_state`).  
  If they differ at any round, a spatial fault is recorded.

* **Temporal redundancy (compute twice, compare)**  
  The dual-core block above is run **twice** on the same input.  
  The first ciphertext is stored in `ct1_reg`; the second run’s ciphertext is compared to it.  
  If the two ciphertexts differ, a temporal fault is recorded.

* **Fault outcome**  
  If either a spatial fault (in run 1 or run 2) or a temporal fault (ct1 ≠ ct2) is detected:  
  `fault_flag=1` and the output ciphertext is forced to `0`.  
  Otherwise: `fault_flag=0` and the ciphertext is the (consistent) result.

This combination targets **transient fault injection** and makes it harder for an attacker to bypass both per-round comparison and end-to-end comparison.

### Flow and Key Signals

* **FSM (in `aes_top.v`)**  
  `ST_IDLE` → `ST_RUN1` → `ST_WAIT1` → `ST_RUN2` → `ST_WAIT2` → `ST_IDLE`.  
  Run1 and Run2 each use the same two cores in lockstep; Run2 starts when Run1’s `core_done` is seen.

* **Signals (conceptual)**  
  * `fault_detected`: set when `core_A_state != core_B_state` during a run; cleared at the start of each run.  
  * `fault_spatial_1`: holds the spatial-fault flag from Run1 when leaving `ST_WAIT1`.  
  * `ct1_reg`: ciphertext from Run1, used for temporal comparison when Run2 completes.  
  * `fault_flag` (output): `1` if `fault_spatial_1` or `fault_detected` (Run2) or `(core_A_ciphertext != ct1_reg)`; else `0`.  
  When `fault_flag=1`, ciphertext output is suppressed (forced to zero).

### Interface

`aes_top` exposes:

* `fault_flag`: indicates that a fault was detected (spatial and/or temporal); valid on `done`.

### How to Run

Baseline correctness against OpenSSL:

```bash
./run.sh
```

Fault-injection validation:

```bash
./run_fault.sh
```

### Fault Injection Method (Simulation)

`tb/tb_fault.sv` injects a transient fault via `force/release` on **core A’s** state register  
(`dut.u_core_A.state_reg`) during encryption. The lockstep comparison with core B detects the mismatch and the design sets `fault_flag=1`.

---

## Power Side-Channel Defenses: Randomized Timing & Power Noise

### Randomized Timing (Cycle-Level Stall)

A pseudo-random stall mechanism is added to the AES core execution to obscure timing patterns.

- A 16-bit LFSR generates a pseudo-random sequence
- Each round advances only when `step_en == 1`
- When `step_en == 0`, the core stalls for that cycle
- Stall decisions are applied **only while the core is busy**

This introduces execution time variability while preserving functional correctness.

**Implementation details**

- 16-bit Fibonacci LFSR  
- Primitive polynomial:  
  `x^16 + x^14 + x^13 + x^11 + 1`
- Stall probability ≈ 25% (advance ≈ 75%)

```verilog
step_en_next = 1'b1;
if (core_busy) begin
  step_en_next = (lfsr[0] | lfsr[1]);  // 75% advance, 25% stall
end
step_en_r <= step_en_next;
```

The AES datapath itself is unchanged — only the round controller gating was modified.

### Dummy Switching Power Noise

Additional switching activity is generated during encryption to mask data-dependent power behavior.

- A 512-bit register (`noise_reg`) toggles during execution

- Functionally isolated from the AES datapath

- Produces background dynamic power activity

``` verilog
if (core_busy) begin
  if (step_en_next)        // active cycle
    noise_reg <= noise_reg ^ weak_mask;   // partial toggling
  else                     // stall cycle
    noise_reg <= ~noise_reg;              // maximal toggling
end
```

This creates higher and more variable switching activity, especially during stall cycles.

### Power Activity Instrumentation (`power_flag`)

To emulate attacker-visible power measurements, the design exposes per-cycle switching activity.

#### New Output Signal

aes_top provides an additional output:

```verilog
output reg [9:0] power_flag
```

`power_flag` reports the number of flipped bits in noise_reg during the current cycle.

```
Dynamic Power ∝ Switching Activity
```
#### Flip Count Computation

Each cycle:

```verilog
flip_count = HammingDistance(noise_reg_next, noise_reg_current)
```

Two operating modes:

- Active cycle: partial/random flips

- Stall cycle: large-scale inversion → high activity

This signal does not affect functionality and is intended for analysis only.

### Security / Research Purpose

These mechanisms support experiments on side-channel resistance, including:

- Timing obfuscation

- Power noise injection

- Correlation attack mitigation

- Effectiveness of randomized execution

External observers (testbench) can measure:

- Total switching activity

- Average activity per cycle

- Distribution across executions

---
### How to Run

```bash
./run_power.sh
```

Optional: specify number of test vectors:

```
./run_power.sh 200
```

### Output Interpretation

During simulation, the testbench prints per-encryption statistics:

```
[POWER] flips_total=10112 avg_flips_per_cycle=297 (pwr_cycles=34)
```
Where:

- flips_total — total bit transitions observed

- pwr_cycles — number of active (busy) cycles

- avg_flips_per_cycle — average switching activity

At the end, global statistics are reported:

```
=== Power Proxy Stats (attacker-observed) ===
Total flips: XXXXX
Total busy cycles: XXXXX
Avg flips/cycle: XXX
```

### Waveform Analysis

The simulation also generates:
```
power.vcd
```
This file can be viewed with GTKWave:
```
gtkwave power.vcd
```
It contains signal activity for further side-channel analysis.


### Result Vitualization

#### Distribution Statistics

Tracks overall timing characteristics:

- Minimum latency
- Maximum latency
- Average latency
- Histogram of cycle counts

#### Visual Star Histogram

Displays occurrence counts using `*`:

```
  Latency 32 cycles : ********** (10)
```


#### Deadlock Protection

Timeout logic prevents simulation hangs if `done` never asserts.

---
