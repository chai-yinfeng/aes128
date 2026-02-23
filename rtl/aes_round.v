// aes_round.v
// AES encryption round function.
//
// Inputs:
//   state_in      : 128-bit state
//   round_key_in  : rk[round] (128-bit)
//   final_round   : 1 => skip MixColumns (AES final round)
//
// Output:
//   state_out     : new state after the round
//
// Byte layout:
//   byte i of state_in is state_in[127-8*i -: 8], i=0..15
// AES state mapping (column-major):
//   indices in same column: (0,1,2,3), (4,5,6,7), (8,9,10,11), (12,13,14,15)
// rows:
//   row0: 0,4,8,12
//   row1: 1,5,9,13
//   row2: 2,6,10,14
//   row3: 3,7,11,15

`timescale 1ns/1ps

module aes_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key_in,
    input  wire         final_round,
    output wire [127:0] state_out
);

  // ----------------------------
  // Unpack state bytes.
  // ----------------------------
  wire [7:0] b0  = state_in[127:120];
  wire [7:0] b1  = state_in[119:112];
  wire [7:0] b2  = state_in[111:104];
  wire [7:0] b3  = state_in[103:96];
  wire [7:0] b4  = state_in[95:88];
  wire [7:0] b5  = state_in[87:80];
  wire [7:0] b6  = state_in[79:72];
  wire [7:0] b7  = state_in[71:64];
  wire [7:0] b8  = state_in[63:56];
  wire [7:0] b9  = state_in[55:48];
  wire [7:0] b10 = state_in[47:40];
  wire [7:0] b11 = state_in[39:32];
  wire [7:0] b12 = state_in[31:24];
  wire [7:0] b13 = state_in[23:16];
  wire [7:0] b14 = state_in[15:8];
  wire [7:0] b15 = state_in[7:0];

  // ----------------------------
  // SubBytes: 16 parallel S-box lookups.
  // ----------------------------
  wire [7:0] sb0, sb1, sb2, sb3, sb4, sb5, sb6, sb7, sb8, sb9, sb10, sb11, sb12, sb13, sb14, sb15;

  aes_sbox s0 (.in_byte(b0 ), .out_byte(sb0 ));
  aes_sbox s1 (.in_byte(b1 ), .out_byte(sb1 ));
  aes_sbox s2 (.in_byte(b2 ), .out_byte(sb2 ));
  aes_sbox s3 (.in_byte(b3 ), .out_byte(sb3 ));
  aes_sbox s4 (.in_byte(b4 ), .out_byte(sb4 ));
  aes_sbox s5 (.in_byte(b5 ), .out_byte(sb5 ));
  aes_sbox s6 (.in_byte(b6 ), .out_byte(sb6 ));
  aes_sbox s7 (.in_byte(b7 ), .out_byte(sb7 ));
  aes_sbox s8 (.in_byte(b8 ), .out_byte(sb8 ));
  aes_sbox s9 (.in_byte(b9 ), .out_byte(sb9 ));
  aes_sbox s10(.in_byte(b10), .out_byte(sb10));
  aes_sbox s11(.in_byte(b11), .out_byte(sb11));
  aes_sbox s12(.in_byte(b12), .out_byte(sb12));
  aes_sbox s13(.in_byte(b13), .out_byte(sb13));
  aes_sbox s14(.in_byte(b14), .out_byte(sb14));
  aes_sbox s15(.in_byte(b15), .out_byte(sb15));

  // ----------------------------
  // ShiftRows: fixed byte permutation.
  // Row0 unchanged: (0,4,8,12)
  // Row1 left shift by 1: (1,5,9,13) -> (5,9,13,1)
  // Row2 left shift by 2: (2,6,10,14) -> (10,14,2,6)
  // Row3 left shift by 3: (3,7,11,15) -> (15,3,7,11)
  // ----------------------------
  wire [7:0] sr0  = sb0;
  wire [7:0] sr4  = sb4;
  wire [7:0] sr8  = sb8;
  wire [7:0] sr12 = sb12;

  wire [7:0] sr1  = sb5;
  wire [7:0] sr5  = sb9;
  wire [7:0] sr9  = sb13;
  wire [7:0] sr13 = sb1;

  wire [7:0] sr2  = sb10;
  wire [7:0] sr6  = sb14;
  wire [7:0] sr10 = sb2;
  wire [7:0] sr14 = sb6;

  wire [7:0] sr3  = sb15;
  wire [7:0] sr7  = sb3;
  wire [7:0] sr11 = sb7;
  wire [7:0] sr15 = sb11;

  // ----------------------------
  // MixColumns helpers (GF(2^8)).
  // xtime(x): multiply by {02} in Rijndael field (mod 0x11B).
  // mul3(x) = xtime(x) ^ x
  // ----------------------------
  function [7:0] xtime(input [7:0] x);
    begin
      xtime = {x[6:0], 1'b0} ^ (8'h1B & {8{x[7]}});
    end
  endfunction

  function [31:0] mixcol(input [31:0] col);
    // col = {s0,s1,s2,s3} (bytes)
    reg [7:0] s0, s1, s2, s3;
    reg [7:0] t0, t1, t2, t3;
    reg [7:0] m2_0, m2_1, m2_2, m2_3;
    reg [7:0] m3_0, m3_1, m3_2, m3_3;
    begin
      s0 = col[31:24];
      s1 = col[23:16];
      s2 = col[15:8];
      s3 = col[7:0];

      m2_0 = xtime(s0);  m2_1 = xtime(s1);  m2_2 = xtime(s2);  m2_3 = xtime(s3);
      m3_0 = m2_0 ^ s0;  m3_1 = m2_1 ^ s1;  m3_2 = m2_2 ^ s2;  m3_3 = m2_3 ^ s3;

      // AES MixColumns:
      // t0 = 2*s0 + 3*s1 + 1*s2 + 1*s3
      // t1 = 1*s0 + 2*s1 + 3*s2 + 1*s3
      // t2 = 1*s0 + 1*s1 + 2*s2 + 3*s3
      // t3 = 3*s0 + 1*s1 + 1*s2 + 2*s3
      t0 = m2_0 ^ m3_1 ^ s2   ^ s3;
      t1 = s0   ^ m2_1 ^ m3_2 ^ s3;
      t2 = s0   ^ s1   ^ m2_2 ^ m3_3;
      t3 = m3_0 ^ s1   ^ s2   ^ m2_3;

      mixcol = {t0, t1, t2, t3};
    end
  endfunction

  // Apply MixColumns per column unless final_round==1.
  wire [31:0] col0_in = {sr0,  sr1,  sr2,  sr3};
  wire [31:0] col1_in = {sr4,  sr5,  sr6,  sr7};
  wire [31:0] col2_in = {sr8,  sr9,  sr10, sr11};
  wire [31:0] col3_in = {sr12, sr13, sr14, sr15};

  wire [31:0] col0_mc = mixcol(col0_in);
  wire [31:0] col1_mc = mixcol(col1_in);
  wire [31:0] col2_mc = mixcol(col2_in);
  wire [31:0] col3_mc = mixcol(col3_in);

  wire [7:0] mc0  = col0_mc[31:24];
  wire [7:0] mc1  = col0_mc[23:16];
  wire [7:0] mc2  = col0_mc[15:8];
  wire [7:0] mc3  = col0_mc[7:0];

  wire [7:0] mc4  = col1_mc[31:24];
  wire [7:0] mc5  = col1_mc[23:16];
  wire [7:0] mc6  = col1_mc[15:8];
  wire [7:0] mc7  = col1_mc[7:0];

  wire [7:0] mc8  = col2_mc[31:24];
  wire [7:0] mc9  = col2_mc[23:16];
  wire [7:0] mc10 = col2_mc[15:8];
  wire [7:0] mc11 = col2_mc[7:0];

  wire [7:0] mc12 = col3_mc[31:24];
  wire [7:0] mc13 = col3_mc[23:16];
  wire [7:0] mc14 = col3_mc[15:8];
  wire [7:0] mc15 = col3_mc[7:0];

  // Select SR (final round) vs MC (normal round).
  wire [127:0] pre_ark_state =
      final_round ?
      {sr0,  sr1,  sr2,  sr3,
       sr4,  sr5,  sr6,  sr7,
       sr8,  sr9,  sr10, sr11,
       sr12, sr13, sr14, sr15}
      :
      {mc0,  mc1,  mc2,  mc3,
       mc4,  mc5,  mc6,  mc7,
       mc8,  mc9,  mc10, mc11,
       mc12, mc13, mc14, mc15};

  // AddRoundKey (XOR in GF(2)).
  assign state_out = pre_ark_state ^ round_key_in;

endmodule
