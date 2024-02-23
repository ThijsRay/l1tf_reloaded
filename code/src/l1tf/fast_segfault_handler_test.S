.global main

.text

main:
  movq $10000000, %r11
  movq $0, %rcx

  movq $0xC7DB70C9B1ABE849, %r12
  movq $0x47DF1DF4CD7E16F1, %r13
  leaq handler(%rip), %r14

loop:
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
