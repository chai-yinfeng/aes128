// aes_core.v
// AES-128 encryption core (iterative, 1 round per cycle).
//
// Dataflow:
// - On start (when idle):
//     state <= plaintext ^ key   // AddRoundKey (round 0)
//     round_key <= key           // holds rk[0]
//     round <= 1
// - For round = 1..10:
//     rk_next = KeyExpand128(round_key, rcon(round))   // rk[round]
//     state   = Round(state, rk_next, final=(round==10))
//     round_key <= rk_next
// - When round==10 finishes, ciphertext <= state and done pulses.
//
// Notes on byte/state layout:
// - We assume the 128-bit vector is a big-endian byte sequence:
//     byte0 = [127:120], ..., byte15 = [7:0]
// - AES state is interpreted in column-major order per the AES spec:
//     state[r,c] = byte[4*c + r]
// This matches common test vectors when you load plaintext/key as hex
// in big-endian byte order.

module aes_core (
    input  wire         clk,
    input  wire         rst,        // synchronous reset, active-high
    input  wire         start,
    input  wire [127:0] key,
    input  wire [127:0] plaintext,
    output reg          busy,
    output reg          done,
    output reg  [127:0] ciphertext
);

  // Internal state and round key registers.
  reg [127:0] state_reg;
  reg [127:0] round_key_reg;   // holds rk[round-1]
  reg [3:0]   round_ctr_reg;   // 1..10

  // Combinational signals for next round.
  wire [7:0]   rcon_byte;
  wire [127:0] rk_next;
  wire [127:0] state_next;

  // Rcon lookup for AES-128 rounds 1..10:
  // 01,02,04,08,10,20,40,80,1B,36
  function [7:0] rcon_lut(input [3:0] r);
    begin
      case (r)
        4'd1:  rcon_lut = 8'h01;
        4'd2:  rcon_lut = 8'h02;
        4'd3:  rcon_lut = 8'h04;
        4'd4:  rcon_lut = 8'h08;
        4'd5:  rcon_lut = 8'h10;
        4'd6:  rcon_lut = 8'h20;
        4'd7:  rcon_lut = 8'h40;
        4'd8:  rcon_lut = 8'h80;
        4'd9:  rcon_lut = 8'h1B;
        4'd10: rcon_lut = 8'h36;
        default: rcon_lut = 8'h00;
      endcase
    end
  endfunction

  assign rcon_byte = rcon_lut(round_ctr_reg);

  // Key expansion (rk_next = rk[round]).
  aes_key_expand_128 u_keyexp (
      .key_in   (round_key_reg),
      .rcon     (rcon_byte),
      .key_out  (rk_next)
  );

  // Round function for encryption.
  aes_round u_round (
      .state_in     (state_reg),
      .round_key_in (rk_next),
      .final_round  (round_ctr_reg == 4'd10),
      .state_out    (state_next)
  );

  // Sequential control.
  always @(posedge clk) begin
    if (rst) begin
      busy         <= 1'b0;
      done         <= 1'b0;
      ciphertext   <= 128'b0;
      state_reg    <= 128'b0;
      round_key_reg<= 128'b0;
      round_ctr_reg<= 4'd0;
    end else begin
      done <= 1'b0; // default (pulse on completion)

      // Start accepted only when idle.
      if (start && !busy) begin
        busy          <= 1'b1;
        round_ctr_reg <= 4'd1;

        // Round 0: AddRoundKey
        state_reg     <= plaintext ^ key;

        // rk[0]
        round_key_reg <= key;

      end else if (busy) begin
        // Perform one AES round per cycle (round 1..10).
        state_reg      <= state_next;
        round_key_reg  <= rk_next;

        if (round_ctr_reg == 4'd10) begin
          // Completed final round this cycle.
          ciphertext   <= state_next;
          busy         <= 1'b0;
          done         <= 1'b1;
          round_ctr_reg<= 4'd0;
        end else begin
          round_ctr_reg<= round_ctr_reg + 4'd1;
        end
      end
    end
  end

endmodule
