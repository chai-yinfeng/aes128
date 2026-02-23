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
  output reg          fault_flag
);

  // --------------------------------------------------------------------------
  // Internal interface to aes_core (baseline core is unchanged)
  // --------------------------------------------------------------------------
  reg         core_start;
  wire        core_busy;
  wire        core_done;
  wire [127:0] core_ciphertext;

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
  wire [15:0] prn16 = lfsr;
  wire [511:0] weak_mask   = {32{~prn16}};

  aes_core u_core (
    .clk(clk),
    .rst(rst),
    .start(core_start),
    .key(key),
    .plaintext(plaintext),
    .step_en(step_en),
    .busy(core_busy),
    .done(core_done),
    .ciphertext(core_ciphertext)
  );

  // Expose busy: top is busy whenever we're in any non-idle state
  assign busy = (state != ST_IDLE);

  // --------------------------------------------------------------------------
  // Temporal redundancy FSM: compute twice and compare
  // --------------------------------------------------------------------------
  localparam ST_IDLE   = 3'd0;
  localparam ST_RUN1   = 3'd1;
  localparam ST_WAIT1  = 3'd2;
  localparam ST_RUN2   = 3'd3;
  localparam ST_WAIT2  = 3'd4;
  localparam ST_FINISH = 3'd5;

  reg [2:0] state;

  reg [127:0] ct1_reg;

  always @(posedge clk) begin
    if (rst) begin
      state      <= ST_IDLE;
      core_start <= 1'b0;

      ct1_reg    <= 128'b0;
      ciphertext <= 128'b0;
      fault_flag <= 1'b0;
      done       <= 1'b0;
      lfsr <= 16'hACE1;
      step_en_r <= 1'b1;
      noise_reg <= 512'd0;
    end else begin
      // defaults
      core_start <= 1'b0;
      done       <= 1'b0;

      if (core_busy) lfsr <= {lfsr[14:0], lfsr_fb};
      // Use combinational assignment to avoid 1-cycle lag from nonblocking assignments
      step_en_next = 1'b1;
      if (core_busy) begin
        step_en_next = (lfsr[0] | lfsr[1]); // 75% advance, 25% stall
      end
      step_en_r <= step_en_next;

      // Strong noise during stall cycles, weak noise during active cycles
      if (core_busy) begin
        if (step_en_next) // If not stalled: weak flip
          noise_reg <= noise_reg ^ weak_mask;
        else // If stalled: all bits are fliped
          noise_reg <= ~noise_reg;
      end

      case (state)
        ST_IDLE: begin
          fault_flag <= 1'b0;
          // Accept new request only when idle
          if (start) begin
            // launch first computation
            core_start <= 1'b1;
            state      <= ST_RUN1;
          end
        end

        // RUN1: pulse core_start already asserted in previous cycle.
        // Move to WAIT1 and wait for core_done.
        ST_RUN1: begin
          state <= ST_WAIT1;
        end

        ST_WAIT1: begin
          if (core_done) begin
            ct1_reg <= core_ciphertext;

            // Launch second computation
            core_start <= 1'b1;
            state      <= ST_RUN2;
          end
        end

        ST_RUN2: begin
          state <= ST_WAIT2;
        end

        ST_WAIT2: begin
          if (core_done) begin
            // Compare second result to first
            if (core_ciphertext == ct1_reg) begin
              ciphertext <= core_ciphertext;
              fault_flag <= 1'b0;
            end else begin
              ciphertext <= 128'b0;     // suppress valid output on mismatch
              fault_flag <= 1'b1;
            end

            done  <= 1'b1;              // 1-cycle pulse
            state <= ST_IDLE;
          end
        end

        default: begin
          state <= ST_IDLE;
        end
      endcase
    end
  end

endmodule