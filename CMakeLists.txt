cmake_minimum_required(VERSION 3.10)
project(thesis)

add_compile_options(
  -O2
  --std=gnu17
  -Wall -Wextra -Wpedantic
  -Wformat=2 -Wno-unused-parameter -Wshadow
  -Wwrite-strings -Wstrict-prototypes -Wold-style-definition
  -Wredundant-decls -Wnested-externs -Wmissing-include-dirs
)

add_executable(kvm_leak
  src/kvm_leak.c
  src/time_deque.c
  deps/prune-plumtree/plumtree.c
  deps/prune-plumtree/plumtree_utils.c
)
target_link_libraries(kvm_leak rt m)
target_include_directories(kvm_leak PRIVATE include deps/prune-plumtree)

add_custom_target(pteditor.ko
  WORKING_DIRECTORY ../deps/PTEditor
  COMMAND make pteditor
)

add_custom_target(modules
  WORKING_DIRECTORY ../src/modules
  COMMAND make
)
