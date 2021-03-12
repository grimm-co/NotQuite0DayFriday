#pragma once

#include <stdint.h>

//Leak the kernel base
uint64_t get_kernel_slide(uint32_t hostno, uint32_t sid, int sock_fd, uint64_t handle);

