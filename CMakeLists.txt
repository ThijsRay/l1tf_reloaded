cmake_minimum_required(VERSION 3.10)
project(thesis)

add_compile_options(
  -O2
  --std=gnu17
  -Wall -Wextra -Wpedantic
  -Wformat=2 -Wno-unused-parameter -Wshadow
  -Wwrite-strings -Wstrict-prototypes -Wold-style-definition
  -Wredundant-decls -Wnested-externs -Wmissing-include-dirs
  -DDEBUG=0
)

add_executable(exploit
  src/exploit.c
  src/helpers.c
  src/l1tf.c
  src/spectre.c
  src/statistics.c
  src/util.c
)

target_link_libraries(exploit rt m)
target_include_directories(exploit PRIVATE include deps/PTEditor)

add_executable(kvm_leak
  src/kvm_leak.c
  src/time_deque.c
  src/l1tf.c
  src/msr.c
  src/statistics.c
  src/helpers.c
  src/spectre.c
  src/util.c
)

target_link_libraries(kvm_leak rt m)
target_include_directories(kvm_leak PRIVATE include deps/PTEditor)

add_executable(victim
  src/victim.c
)
target_include_directories(victim PRIVATE include)

add_custom_target(pteditor.ko
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/deps/PTEditor
  COMMAND make pteditor
)

add_custom_target(ptedit_header.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/deps/PTEditor
  COMMAND make header
)

include(CheckCSourceRuns)
check_c_source_runs(
  "
#include <stdio.h>
#include <stdint.h>

// Function to execute the cpuid instruction
static inline void cpuid(uint32_t eax, uint32_t ecx, uint32_t *ebx, uint32_t *edx) {
    uint32_t _eax, _ebx, _ecx, _edx;
    asm volatile(\"cpuid\"
                 : \"=a\"(_eax), \"=b\"(_ebx), \"=c\"(_ecx), \"=d\"(_edx)
                 : \"a\"(eax), \"c\"(ecx));
    *ebx = _ebx;
    *edx = _edx;
}

// Function to check for SMAP support
int check_smap_support() {
    uint32_t ebx = 0, edx = 0;
    cpuid(0x7, 0x0, &ebx, &edx);

    // Check if the 20th bit of EBX is set (indicates SMAP support)
    return (ebx & (1 << 20)) != 0;
}

int main() {
    if (check_smap_support()) {
      return 0;
    } else {
      return 1;
    }
}"
  HAS_SMAP
)

# Kernel modules
file(WRITE
  ${CMAKE_BINARY_DIR}/Kbuild.in
"obj-m := @module_name@.o
ccflags-y += -I@CMAKE_SOURCE_DIR@/include
ccflags-y += -DHAS_SMAP=${HAS_SMAP}"
)

set(kerneldir "" CACHE STRING "Path to the kernel build directory")
if("${kerneldir}" STREQUAL "")
  execute_process(COMMAND uname -r OUTPUT_VARIABLE uname_r
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(kerneldir "/lib/modules/${uname_r}/build")
endif()
find_file(kernel_makefile NAMES Makefile
                          PATHS ${kerneldir} NO_DEFAULT_PATH)
if(NOT kernel_makefile)
  message(FATAL_ERROR "There is no Makefile in the kernel build directory!")
endif()

function(compile_kernel_module module_name module_sources)
configure_file(${CMAKE_BINARY_DIR}/Kbuild.in
  ${CMAKE_BINARY_DIR}/${module_name}/Kbuild @ONLY)

foreach(src ${module_sources})
  configure_file(src/modules/${module_name}/${src} ${module_name}/${src} COPYONLY)
endforeach()

set(module_cmd ${CMAKE_MAKE_PROGRAM} -C ${kerneldir} M=${CMAKE_CURRENT_BINARY_DIR}/${module_name})
add_custom_command(OUTPUT ${module_name}.ko
  COMMAND ${module_cmd} modules
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${module_name}
  DEPENDS src/modules/${module_name}/${module_sources} ${CMAKE_CURRENT_BINARY_DIR}/${module_name}/Kbuild
  VERBATIM)
add_custom_target(${module_name} DEPENDS ${module_name}.ko)
add_custom_target(${module_name}-clean COMMAND ${module_cmd} clean)
endfunction()

compile_kernel_module(hypercall "hypercall.c")
compile_kernel_module(kvm_assist "kvm_assist.c")

#
# add_library(hypercall-lib STATIC source1.c source2.c)
# get_target_property(module_sources mymodule-lib SOURCES)
# list(APPEND module_sources module.c)
#
# add_custom_target(hypercall.ko
#   WORKING_DIRECTORY ../src/modules/hypercall
#   COMMAND  ${CMAKE_COMMAND} -E env HAS_SMAP=${HAS_SMAP} make
# )
#
