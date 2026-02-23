// aes_top.v
// Minimal AES-128 encryptor wrapper
// - Accepts a single 128-bit block and 128-bit key
// - start is sampled when not busy
// - done pulses for one cycle when ciphertext is valid

module aes_top (
    input wire          clk,
    input wire          rst,         // synchronous reset, active-high
    input wire          start,       // pulse to begin encryption
    input wire [127:0]  key,         // AES-128 key
    input wire [127:0]  plaintext,   // 128-bit input block
    output wire         done,
    output wire         busy,
    output wire [127:0] ciphertext
);

    aes_core u_core (
        .clk(clk),
        .rst(rst),
        .start(start),
        .key(key),
        .plaintext(plaintext),
        .done(done),
        .busy(busy),
        .ciphertext(ciphertext)
    );

endmodule