`timescale 1ns/1ps

module tb_aes128;

  // Clock / reset
  reg clk = 0;
  always #5 clk = ~clk;  // 100MHz

  reg rst;

  // DUT I/O
  reg         start;
  reg [127:0] key;
  reg [127:0] plaintext;
  wire        busy;
  wire        done;
  wire [127:0] ciphertext;

  // Instantiate DUT
  aes_top dut (
    .clk(clk),
    .rst(rst),
    .start(start),
    .key(key),
    .plaintext(plaintext),
    .busy(busy),
    .done(done),
    .ciphertext(ciphertext),
    .fault_flag(fault_flag)
  );

  // Helpers
  integer fd;
  integer r;
  integer total, pass, fail;

  reg [127:0] exp_ct;
  reg [127:0] got_ct;

  // Task: one encryption transaction
  task automatic run_one(input [127:0] k, input [127:0] pt, input [127:0] expected);
    begin
      // Apply inputs
      key       = k;
      plaintext = pt;

      // Pulse start for 1 cycle
      @(negedge clk);
      start = 1'b1;
      @(negedge clk);
      start = 1'b0;

      // Wait for done
      while (done !== 1'b1) begin
        @(posedge clk);
      end

      got_ct = ciphertext;

      if (got_ct === expected) begin
        pass = pass + 1;
      end else begin
        fail = fail + 1;
        $display("[FAIL] key=%032x pt=%032x exp=%032x got=%032x",
                  k, pt, expected, got_ct);
      end
      total = total + 1;
    end
  endtask

  initial begin
    // init
    rst = 1'b1;
    start = 1'b0;
    key = 128'b0;
    plaintext = 128'b0;

    total = 0;
    pass  = 0;
    fail  = 0;

    // reset for a few cycles
    repeat (5) @(posedge clk);
    rst = 1'b0;
    repeat (2) @(posedge clk);

    // Open vectors file
    fd = $fopen("vectors.txt", "r");
    if (fd == 0) begin
      $display("ERROR: cannot open vectors.txt");
      $finish;
    end

    // Each line: key pt ct (hex, 32 chars each)
    // %h can read into 128-bit reg directly if the token is hex without 0x.
    while (!$feof(fd)) begin
      r = $fscanf(fd, "%h %h %h\n", key, plaintext, exp_ct);
      if (r == 3) begin
        run_one(key, plaintext, exp_ct);
      end
    end

    $fclose(fd);

    $display("=== AES-128 RTL vs OpenSSL ===");
    $display("Total: %0d  Pass: %0d  Fail: %0d", total, pass, fail);

    if (fail == 0) $display("RESULT: PASS");
    else           $display("RESULT: FAIL");

    $finish;
  end

endmodule
