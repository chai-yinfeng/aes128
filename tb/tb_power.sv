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
  wire [9:0]  power_flag;

  // Declare fault_flag to avoid implicit wire warning
  wire fault_flag;

  // Add some variables to record latency stats and timeout
  integer lat_min, lat_max;
  integer lat_sum;
  integer lat_hist[0:63];
  integer i;
  integer j;
  integer pwr_sum_all;
  integer pwr_cycles_all;
  localparam integer TIMEOUT_CYCLES = 2000;

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
    .fault_flag(fault_flag),
    .power_flag(power_flag)
  );

  // Helpers
  integer fd;
  integer r;
  integer total, pass, fail;

  reg [127:0] exp_ct;
  reg [127:0] got_ct;

  // Task: one encryption transaction
  task automatic run_one(input [127:0] k, input [127:0] pt, input [127:0] expected);
    integer cycles;
    integer pwr_sum;
    integer pwr_cycles;

    begin
      // Apply inputs
      key       = k;
      plaintext = pt;

      // Pulse start for 1 cycle
      @(negedge clk);
      start = 1'b1;
      @(negedge clk);
      start = 1'b0;
      
      pwr_sum    = 0;
      pwr_cycles = 0;

      // Wait for done with timeout and measure latency
      cycles = 0;
      while (done !== 1'b1) begin
        @(posedge clk);
        cycles = cycles + 1;
        pwr_sum    = pwr_sum + power_flag;
        pwr_cycles = pwr_cycles + 1;
        if (cycles > TIMEOUT_CYCLES) begin
          $display("[TIMEOUT] key=%032x pt=%032x (no done after %0d cycles) busy=%0d",
                   k, pt, TIMEOUT_CYCLES, busy);
          $finish;
        end
      end

      // Print per-transaction observed power stats
      $display("[POWER] flips_total=%0d avg_flips_per_cycle=%0d (pwr_cycles=%0d)",
               pwr_sum,
               (pwr_cycles ? (pwr_sum / pwr_cycles) : 0),
               pwr_cycles);

      // Accumulate global stats
      pwr_sum_all    = pwr_sum_all + pwr_sum;
      pwr_cycles_all = pwr_cycles_all + pwr_cycles;

      // Record latency stats
      if (cycles < lat_min) lat_min = cycles;
      if (cycles > lat_max) lat_max = cycles;
      lat_sum = lat_sum + cycles;

      if (cycles > 63) lat_hist[63] = lat_hist[63] + 1;
      else             lat_hist[cycles] = lat_hist[cycles] + 1;

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
    // ----------------------------------------------------------------------
    // Dump VCD waveform (proxy for switching activity / "power")
    // ----------------------------------------------------------------------
    $dumpfile("power.vcd");
    $dumpvars(0, tb_aes128);

    // init
    rst = 1'b1;
    start = 1'b0;
    key = 128'b0;
    plaintext = 128'b0;

    total = 0;
    pass  = 0;
    fail  = 0;
    pwr_sum_all    = 0;
    pwr_cycles_all = 0;

    lat_min = 1<<30;
    lat_max = 0;
    lat_sum = 0;
    for (i = 0; i < 64; i = i + 1) lat_hist[i] = 0;

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

    // Overall average observed power proxy
    $display("=== Power Proxy Stats (attacker-observed) ===");
    $display("Total flips: %0d  Total busy cycles: %0d  Avg flips/cycle: %0d",
             pwr_sum_all, pwr_cycles_all, (pwr_cycles_all ? (pwr_sum_all / pwr_cycles_all) : 0));

    $display("=== Random Stall Latency Stats (cycles from start->done) ===");
    $display("Min: %0d  Avg: %0d  Max: %0d",
             lat_min, (total ? (lat_sum/total) : 0), lat_max);

    $display("Latency distribution (star bar, * = 1 occurrence) [63 includes 63+]");

    for (i = 0; i < 64; i = i + 1) begin
      if (lat_hist[i] != 0) begin
        $write("  Latency %0d cycles : ", i);

        // Print one '*' per occurrence
        for (j = 0; j < lat_hist[i]; j = j + 1)
          $write("*");

        // Also print numeric count for clarity
        $display(" (%0d)", lat_hist[i]);
      end
    end

    if (fail == 0) $display("RESULT: PASS");
    else           $display("RESULT: FAIL");

    $finish;
  end

endmodule
