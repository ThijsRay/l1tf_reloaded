#pragma once

#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define GET_PHYS_FAILED 0xffffffffffffff

/*
 * For each page in the address space, /proc/pid/pagemap contains one 
 * 64-bit entry consisting of the following:
 *
 * Bits 0-54  page frame number (PFN) if present
 * Bits 0-4   swap type if swapped
 * Bits 5-54  swap offset if swapped
 * Bit  55    pte is soft-dirty (see Documentation/admin-guide/mm/soft-dirty.rst)
 * Bit  56    page exclusively mapped
 * Bit  57    pte is uffd-wp write-protected
 * Bits 58-60 zero
 * Bit  61    page is file-page or shared-anon
 * Bit  62    page swapped
 * Bit  63    page present
 *
 * This struct encodes this
*/
typedef struct __attribute__((__packed__)) pagemap_entry_t {
  uint64_t pfn : 55;
  bool soft_dirty : 1;
  bool exclusively_mapped : 1;
  bool write_protected : 1;
  uint8_t zero : 3;
  bool file_page_or_shared_anon : 1;
  bool swapped : 1;
  bool present : 1;
} pagemap_entry_t;
_Static_assert(sizeof(pagemap_entry_t) == 8,
               "pagemap_entry_t has an incorrect size");

pagemap_entry_t get_pagemap_entry(pid_t pid, void *virtual_address) {
  char *path;
  assert(asprintf(&path, "/proc/%d/pagemap", pid) > 0);
  assert(path != NULL);

  FILE *file = fopen(path, "rb");
  assert(file);

  // Seek to the correct location in the pagemap
  uintptr_t offset =
      ((uintptr_t)virtual_address / getpagesize()) * sizeof(pagemap_entry_t);
  assert(!fseek(file, offset, SEEK_SET));

  pagemap_entry_t entry;
  int objects_read = fread(&entry, sizeof(pagemap_entry_t), 1, file);
  assert(objects_read == 1);

  assert(!fclose(file));
  free(path);

  return entry;
}

uintptr_t get_physical_addresss(pid_t pid, void *virtual_address) {
  pagemap_entry_t entry = get_pagemap_entry(pid, virtual_address);
  uintptr_t offset = (uintptr_t)virtual_address % getpagesize();
  uint64_t pfn = entry.pfn;
  printf("entry: %lx\tpfn: %lx\n", *(uint64_t *)&entry, pfn);
  return (entry.pfn * getpagesize()) + offset;
}
