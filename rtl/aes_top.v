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

  aes_core u_core (
    .clk(clk),
    .rst(rst),
    .start(core_start),
    .key(key),
    .plaintext(plaintext),
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
    end else begin
      // defaults
      core_start <= 1'b0;
      done       <= 1'b0;

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