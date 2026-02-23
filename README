# HW-2 AES-128 RTL (Baseline)

This repository contains a minimal, stable **AES-128 encryption** RTL implementation and a reproducible validation setup against **OpenSSL** (reference implementation).
**No defenses are implemented in this baseline.** The goal is to establish a correct AES-128 core before adding countermeasures.

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
├─ scripts/
│  └─ gen_vectors.py         # generates OpenSSL reference vectors (ECB, 1-block, no pad)
├─ run.sh                    # one-command: generate vectors, compile, simulate
├─ run_fault.sh              # based on run.sh, but add verification for fault defense
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

## Fault Defense: Temporal Redundancy (Compute-and-Compare)

### Summary

A fault-detection countermeasure is implemented using **temporal redundancy**:

* Run AES-128 encryption **twice** on the same `(key, plaintext)`
* Compare the two ciphertexts

  * If equal: output ciphertext and set `fault_flag=0`
  * If mismatch: set `fault_flag=1` and suppress valid output (ciphertext is forced to `0`)

This targets **transient fault injection** (e.g., single-cycle bit flips during computation).

### Interface

`aes_top` exposes an additional output:

* `fault_flag`: indicates mismatch between the two computations

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

`tb/tb_fault.sv` injects a transient fault via `force/release` on the internal state register
during the encryption window, then checks that `fault_flag` asserts.
