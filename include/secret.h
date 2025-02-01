#pragma once

#include <stdint.h>

// This is fake "secret" data that is only known by the victim.
// After the attacker has leaked everything, we use this data to show to
// the user how we did. We will not use the data to make any decisions
// about the leaking process, the attacker does not use this "secret" data
// during the attack phase.
volatile uint8_t SECRET_DATA[] = {
    0x6e, 0x25, 0xda, 0xcd, 0x55, 0x52, 0x10, 0x8a, 0x11, 0x76, 0x41, 0x2c, 0x03, 0xc5, 0xf8, 0x50,
    'T',  'h',  'i',  's',  ' ',  'i',  's',  ' ',  'a',  ' ',  's',  'u',  'p',  'e',  'r',  ' ',
    's',  'e',  'c',  'r',  'e',  't',  ' ',  'p',  'a',  's',  's',  'w',  'o',  'r',  'd',  ' ',
    't',  'h',  'a',  't',  ' ',  'n',  'o',  'b',  'o',  'd',  'y',  ' ',  's',  'h',  'o',  'u',
    'l',  'd',  ' ',  'e',  'v',  'e',  'r',  ' ',  'k',  'n',  'o',  'w',  ':',  0x20, 0xde, 0xad,
    0xbe, 0xef, 0x67, 0x04, 0x3e, 0x1c, 0x2a, 0x2e, 0x4e, 0x86, 0x3d, 0x99, 0x3f, 0xac, 0x1b, 0x8b,
    0xce, 0xb6, 0x84, 0xf8, 0x2f, 0xf9, 0x95, 0x97, 0x08, 0x63, 0xad, 0xb3, 0x31, 0xc7, 0xfe, 0x5c,
    0xf8, 0x67, 0xb2, 0x74, 0x69, 0xb1, 0x4c, 0x33, 0xae, 0x4d, 0x00, 0x43, 0xba, 0xbe, 0xca, 0xfe};

// If we're printing all characters AS IS, then we might modify things like
// the current cursor position of the terminal.
void escape_ascii(char in, char out[3]) {
  out[1] = 0;
  out[2] = 0;

  switch (in) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 14:
  case 15:
  case 16:
  case 17:
  case 18:
  case 19:
  case 20:
  case 21:
  case 22:
  case 23:
  case 24:
  case 25:
  case 26:
  case 27:
  case 28:
  case 29:
  case 30:
  case 31:
  case 127:
    out[0] = ' ';
    break;
  case 7:
    out[0] = '\\';
    out[1] = 'a';
    break;
  case 8:
    out[0] = '\\';
    out[1] = 'b';
    break;
  case 9:
    out[0] = '\\';
    out[1] = 't';
    break;
  case 10:
    out[0] = '\\';
    out[1] = 'n';
    break;
  case 11:
    out[0] = '\\';
    out[1] = 'v';
    break;
  case 12:
    out[0] = '\\';
    out[1] = 'f';
    break;
  case 13:
    out[0] = '\\';
    out[1] = 'r';
    break;
  default:
    out[0] = in;
    break;
  }
}
