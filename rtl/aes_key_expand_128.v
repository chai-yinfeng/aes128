// aes_key_expand_128.v
// AES-128 Key Expansion (one step).
//
// Input : key_in  = rk[i]   (128-bit, words w0..w3)
//         rcon    = Rcon for next round (8-bit)
// Output: key_out = rk[i+1]
//
// AES-128 schedule:
//   temp = SubWord(RotWord(w3)) ^ (Rcon << 24)
//   w0'  = w0 ^ temp
//   w1'  = w1 ^ w0'
//   w2'  = w2 ^ w1'
//   w3'  = w3 ^ w2'
//
// Word layout (big-endian):
//   w0 = key_in[127:96], w1 = [95:64], w2 = [63:32], w3 = [31:0]

module aes_key_expand_128 (
    input  wire [127:0] key_in,
    input  wire [7:0]   rcon,
    output wire [127:0] key_out
);

  wire [31:0] w0 = key_in[127:96];
  wire [31:0] w1 = key_in[95:64];
  wire [31:0] w2 = key_in[63:32];
  wire [31:0] w3 = key_in[31:0];

  // RotWord(w3): rotate left by 1 byte.
  wire [31:0] rotw3 = {w3[23:0], w3[31:24]};

  // SubWord(rotw3): apply S-box to each byte.
  wire [7:0] sb0, sb1, sb2, sb3;

  aes_sbox u_sb0(.in_byte(rotw3[31:24]), .out_byte(sb0));
  aes_sbox u_sb1(.in_byte(rotw3[23:16]), .out_byte(sb1));
  aes_sbox u_sb2(.in_byte(rotw3[15:8 ]), .out_byte(sb2));
  aes_sbox u_sb3(.in_byte(rotw3[7 :0 ]), .out_byte(sb3));

  wire [31:0] subw3 = {sb0, sb1, sb2, sb3};

  // Rcon word: rcon in MSB byte.
  wire [31:0] rconw = {rcon, 24'h000000};

  wire [31:0] temp = subw3 ^ rconw;

  wire [31:0] w0n = w0 ^ temp;
  wire [31:0] w1n = w1 ^ w0n;
  wire [31:0] w2n = w2 ^ w1n;
  wire [31:0] w3n = w3 ^ w2n;

  assign key_out = {w0n, w1n, w2n, w3n};

endmodule
