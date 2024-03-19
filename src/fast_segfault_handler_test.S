.global _start

.text

_start:
  movq $100000000, %r11
  movq $0x0, %rcx

loop:
  movl $0xB1ABE849, %r12d
  movl $0xCD7E16F1, %r13d
  leaq handler(%rip), %r14

  test %r11, %r11
  jz success

  // Do the segfault!
  movq (0x4732987432), %rax

  // Should not go here, give an error code
  movq $0x1, %rax
  ret
  

handler:
  decq %r11
  jmp loop

success:
  movq $0, %rax

_exit:
  movq %rax, %rdi
  movq $60, %rax
  syscall
