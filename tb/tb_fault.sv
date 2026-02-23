`timescale 1ns/1ps

module tb_fault;

  // Clock
  reg clk = 0;
  always #5 clk = ~clk;

  // DUT signals
  reg         rst;
  reg         start;
  reg [127:0] key;
  reg [127:0] plaintext;

  wire        busy;
  wire        done;
  wire [127:0] ciphertext;
  wire        fault_flag;

  // Instantiate DUT (fault-defense top)
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

  // file io
  integer fd;
  integer r;

  reg [127:0] exp_ct;

  integer total_ok, total_fault;
  integer pass_ok,  fail_ok;
  integer pass_fault, fail_fault;

  reg [127:0] snap_state;
  reg [127:0] forced_state;

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  task automatic pulse_start();
    begin
      @(negedge clk);
      start = 1'b1;
      @(negedge clk);
      start = 1'b0;
    end
  endtask

  task automatic wait_done();
    begin
      while (done !== 1'b1) begin
        @(posedge clk);
      end
    end
  endtask

  // Inject a transient fault by flipping one bit of the internal state register
  // for ~1 cycle.
  task automatic inject_transient_fault();
    begin
      // Wait a few cycles after start to be "in the middle" of encryption.
      repeat (4) @(posedge clk);

      // Hierarchical reference into aes_core's state register.
      snap_state   = dut.u_core.state_reg;
      forced_state = snap_state ^ 128'h1;

      // Flip one bit transiently
      force dut.u_core.state_reg = forced_state;
      @(posedge clk);
      release dut.u_core.state_reg;
    end
  endtask

  // --------------------------------------------------------------------------
  // Main
  // --------------------------------------------------------------------------
  initial begin
    rst = 1'b1;
    start = 1'b0;
    key = '0;
    plaintext = '0;

    total_ok = 0; pass_ok = 0; fail_ok = 0;
    total_fault = 0; pass_fault = 0; fail_fault = 0;

    repeat (5) @(posedge clk);
    rst = 1'b0;
    repeat (2) @(posedge clk);

    fd = $fopen("vectors.txt", "r");
    if (fd == 0) begin
      $display("ERROR: cannot open vectors.txt (run ./run.sh or ./run_fault.sh first)");
      $finish;
    end

    // Each line: key pt ct
    while (!$feof(fd)) begin
      r = $fscanf(fd, "%h %h %h\n", key, plaintext, exp_ct);

      // NOTE: avoid 'continue' (iverilog compatibility); only run when r==3.
      if (r == 3) begin
        // -------------------------
        // Case A: No fault expected
        // -------------------------
        total_ok++;

        pulse_start();
        wait_done();

        if ((fault_flag === 1'b0) && (ciphertext === exp_ct)) begin
          pass_ok++;
        end else begin
          fail_ok++;
          $display("[FAIL-OK] key=%032x pt=%032x exp=%032x got=%032x fault_flag=%0d",
                   key, plaintext, exp_ct, ciphertext, fault_flag);
        end

        // -------------------------
        // Case B: Inject transient fault
        // -------------------------
        total_fault++;

        pulse_start();
        inject_transient_fault();
        wait_done();

        if (fault_flag === 1'b1) begin
          pass_fault++;
        end else begin
          fail_fault++;
          $display("[FAIL-FAULT] key=%032x pt=%032x exp=%032x got=%032x fault_flag=%0d",
                   key, plaintext, exp_ct, ciphertext, fault_flag);
        end

        @(posedge clk);
      end
    end

    $fclose(fd);

    $display("=== Fault Defense Validation (Temporal Redundancy) ===");
    $display("No-fault cases : Total=%0d Pass=%0d Fail=%0d", total_ok, pass_ok, fail_ok);
    $display("Fault-injected : Total=%0d Pass=%0d Fail=%0d", total_fault, pass_fault, fail_fault);

    if ((fail_ok == 0) && (fail_fault == 0)) $display("RESULT: PASS");
    else                                     $display("RESULT: FAIL");

    $finish;
  end

endmodule
