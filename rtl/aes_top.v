// aes_top.v
// Minimal AES-128 encryptor wrapper
// - Accepts a single 128-bit block and 128-bit key
// - start is sampled when not busy
// - done pulses for one cycle when ciphertext is valid

`timescale 1ns/1ps

module aes_top(
  input wire          clk,
  input wire          rst,         // synchronous reset, active-high
  input wire          start,       // pulse to begin encryption
  input wire [127:0]  key,         // AES-128 key
  input wire [127:0]  plaintext,   // 128-bit input block
  output wire         busy,
  output reg          done,
  output reg [127:0]  ciphertext,
  output reg          fault_flag,
  output reg [9:0]    power_flag
);

  // --------------------------------------------------------------------------
  // Dual-core lockstep (spatial redundancy): two cores, same inputs, per-round compare
  // --------------------------------------------------------------------------
  reg         core_start;
  wire        core_A_busy;
  wire        core_B_busy;
  wire        core_A_done;
  wire        core_B_done;
  wire [127:0] core_A_ciphertext;
  wire [127:0] core_B_ciphertext;
  wire [127:0] core_A_state;
  wire [127:0] core_B_state;

  wire        core_busy  = core_A_busy;   // both in lockstep
  wire        core_done  = core_A_done;   // both done same cycle
  wire        state_mismatch = (core_A_busy & core_B_busy) & (core_A_state != core_B_state);
  reg         fault_detected;

  // --------------------------------------------------------------------------
  // Linear Feedback Shift Register (LFSR)
  // Pseudo-random generator used to randomize round timing (side-channel hiding)
  //
  // This is a 16-bit Fibonacci LFSR implementing the primitive polynomial:
  //   x^16 + x^14 + x^13 + x^11 + 1
  //
  // Operation:
  // - At every clock cycle, the register shifts left by one bit.
  // - The new LSB is computed as the XOR ("feedback") of selected tap bits.
  // - These tap positions correspond to the non-zero terms of the polynomial.
  // --------------------------------------------------------------------------
  reg [15:0] lfsr;
  reg        step_en_r;
  reg        step_en_next;
  wire       lfsr_fb = lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10];
  wire       step_en = step_en_r;

  // Dummy switching noise generator
  reg [511:0] noise_reg;
  reg [511:0] noise_prev;
  wire [15:0] prn16 = lfsr;
  wire [511:0] weak_mask   = {32{~prn16}};
  wire [511:0] noise_next =
      (core_busy) ?
        (step_en_next ? (noise_reg ^ weak_mask) : (~noise_reg))
      : noise_reg;

  wire [9:0] flips_this_cycle = popcount512(noise_prev ^ noise_next);

  // Count how many bits been flipped
  function [9:0] popcount512(input [511:0] x);
    integer k;
    reg [9:0] c;
    begin
      c = 10'd0;
      for (k = 0; k < 512; k = k + 1)
        c = c + x[k];
      popcount512 = c;
    end
  endfunction

  aes_core u_core_A (
    .clk(clk),
    .rst(rst),
    .start(core_start),
    .key(key),
    .plaintext(plaintext),
    .step_en(step_en),
    .busy(core_A_busy),
    .done(core_A_done),
    .ciphertext(core_A_ciphertext),
    .state(core_A_state)
  );

  aes_core u_core_B (
    .clk(clk),
    .rst(rst),
    .start(core_start),
    .key(key),
    .plaintext(plaintext),
    .step_en(step_en),
    .busy(core_B_busy),
    .done(core_B_done),
    .ciphertext(core_B_ciphertext),
    .state(core_B_state)
  );

  // Expose busy: top is busy whenever we're in any non-idle state
  assign busy = (state != ST_IDLE);

  // --------------------------------------------------------------------------
  // Temporal + spatial redundancy: dual-core lockstep run twice, compare results
  // - Spatial: per-round compare core_A_state vs core_B_state (fault_detected)
  // - Temporal: compare ct1 (first run) vs ct2 (second run)
  // --------------------------------------------------------------------------
  localparam ST_IDLE   = 3'd0;
  localparam ST_RUN1   = 3'd1;
  localparam ST_WAIT1  = 3'd2;
  localparam ST_RUN2   = 3'd3;
  localparam ST_WAIT2  = 3'd4;

  reg [2:0] state;
  reg [127:0] ct1_reg;          // first run ciphertext (temporal compare)
  reg        fault_spatial_1;   // spatial fault seen during first run

  always @(posedge clk) begin
    if (rst) begin
      state          <= ST_IDLE;
      core_start     <= 1'b0;
      ciphertext     <= 128'b0;
      fault_flag     <= 1'b0;
      done           <= 1'b0;
      fault_detected <= 1'b0;
      ct1_reg        <= 128'b0;
      fault_spatial_1<= 1'b0;
      lfsr           <= 16'hACE1;
      step_en_r      <= 1'b1;
      noise_reg      <= 512'd0;
      noise_prev     <= 512'd0;
      power_flag     <= 10'd0;
    end else begin
      core_start <= 1'b0;
      done       <= 1'b0;

      if (core_busy) lfsr <= {lfsr[14:0], lfsr_fb};
      step_en_next = 1'b1;
      if (core_busy) begin
        step_en_next = (lfsr[0] | lfsr[1]); // 75% advance, 25% stall
      end
      step_en_r <= step_en_next;

      // Per-round spatial fault: set when state mismatch; clear at start of each run
      if (state_mismatch)
        fault_detected <= 1'b1;
      else if ((state == ST_IDLE && start) || (state == ST_WAIT1 && core_done))
        fault_detected <= 1'b0;

      // Strong noise during stall cycles, weak noise during active cycles
      if (core_busy) begin
        power_flag <= flips_this_cycle;
        noise_prev <= noise_next;
        if (step_en_next)
          noise_reg <= noise_reg ^ weak_mask;
        else
          noise_reg <= ~noise_reg;
      end

      case (state)
        ST_IDLE: begin
          fault_flag <= 1'b0;
          if (start) begin
            core_start <= 1'b1;
            state      <= ST_RUN1;
          end
        end

        ST_RUN1: begin
          state <= ST_WAIT1;
        end

        ST_WAIT1: begin
          if (core_done) begin
            ct1_reg         <= core_A_ciphertext;
            fault_spatial_1 <= fault_detected;
            core_start      <= 1'b1;
            state           <= ST_RUN2;
          end
        end

        ST_RUN2: begin
          state <= ST_WAIT2;
        end

        ST_WAIT2: begin
          if (core_done) begin
            // Temporal: ct1 vs second run; spatial: fault in run1 or run2
            if (fault_spatial_1 || fault_detected || (core_A_ciphertext != ct1_reg)) begin
              ciphertext <= 128'b0;
              fault_flag <= 1'b1;
            end else begin
              ciphertext <= core_A_ciphertext;
              fault_flag <= 1'b0;
            end
            done  <= 1'b1;
            state <= ST_IDLE;
          end
        end

        default: state <= ST_IDLE;
      endcase
    end
  end

endmodule
