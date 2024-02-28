.global main

.text

main:
  movq $10000000, %r11
  movq $0, %rcx

loop:
  movl $0xB1ABE849, %r12d
  movl $0xCD7E16F1, %r13d
  leaq handler(%rip), %r14

  test %r11, %r11
  jz success

  lfence
  rdtsc
  lfence

  mov %rax, %r10

  // Do the segfault!
  movq (0x4732987432), %rax

  // Should not go here, give an error code
  movq $1, %rax
  ret
  

handler:
  lfence
  rdtsc
  lfence

  sub %r10, %rax
  add %rax, %rcx

  dec %r11
  jmp loop

success:
  // TODO print the value
  movq $69, %rax
  ret
