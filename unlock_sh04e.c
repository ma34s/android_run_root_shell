#include <stdio.h>
#include "unlock.h"

#define DISABLE_UNLOCK_MMC_WRITE

#define KERNEL_ADDR_VIRT        0xc0008000

#define security_ops            0xc08202b8
#define SECURITY_OPS_POS        3
#define NUM_SECURITY_OPS        (0xc08204e4 - security_ops + 1)

static struct {
  unsigned long int lsm_func;
  unsigned long int cap_func;
} lsm_customs[] = {
  { 0xc021bdd0, 0xc0219984 },   // ptrace_access_check
  { 0xc021bdd8, 0xc0219a1c },   // ptrace_traceme
  { 0xc021c5bc, 0xc0219de4 },   // bprm_set_creds
  { 0xc021c3e4, 0xc021bac0 },   // sb_mount
  { 0xc021c26c, 0xc021bac8 },   // sb_umount
  { 0xc021c1fc, 0xc021bad0 },   // sb_pivotroot
  { 0xc021c2d8, 0xc021bbb8 },   // path_symlink
  { 0xc021c168, 0xc021bbd8 },   // path_chmod
  { 0xc021c108, 0xc021bbe8 },   // path_chroot
  { 0xc021bde0, 0xc021a32c },   // task_fix_setuid
};

static int n_lsm_customs = sizeof (lsm_customs) / sizeof (lsm_customs[0]);

static void *
convert_to_kernel_address(void *address, void *mmap_base_address)
{
  return address - mmap_base_address + (void*)KERNEL_ADDR_VIRT;
}

static void *
convert_to_mmaped_address(void *address, void *mmap_base_address)
{
  return mmap_base_address + (address - (void*)KERNEL_ADDR_VIRT);
}

void unlock_lsm(void *mmaped_address)
{
  unsigned long int *p;
  int count = 0;
  int i;

  p = convert_to_mmaped_address((void *)security_ops, mmaped_address);

  if (strcmp("miyabi", (char *)p) != 0) {
    return;
  }

  printf("Found security_ops!\n");

  for (i = SECURITY_OPS_POS; i < NUM_SECURITY_OPS; i++) {
    int j;

    for (j = 0; j < n_lsm_customs; j++) {
      if (p[i] == lsm_customs[j].lsm_func) {
        p[i] = lsm_customs[j].cap_func;
        count++;
        break;
      }
    }
  }

  printf("  %d functions are fixed\n", count);
}

#define mmc_protect_part        0xc0852b94

#define MMC_BOOT_PARTITION      11
#define MMC_RECOVERY_PARTITION  12
#define MMC_SYSTEM_PARTITION    15

struct mmc_protect_inf {
  unsigned long int partition;
  unsigned long int protect;
};

#define MMC_NO_PROTECT          0x00
#define MMC_PROTECT_READ        0x01
#define MMC_PROTECT_WRITE       0x02

static const struct mmc_protect_inf check_mmc_protect_part[] = {
  { 2,                       MMC_PROTECT_WRITE    },
  { 3,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 4,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 5,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 6,                       MMC_PROTECT_WRITE    },
  { 7,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  { 8,                       MMC_PROTECT_WRITE    },
  { 9,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {10,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {11,    MMC_PROTECT_READ | MMC_PROTECT_WRITE    },
  {12,                       MMC_PROTECT_WRITE    },
  {13,                       MMC_PROTECT_WRITE    },
  {15,                       MMC_PROTECT_WRITE    },
};

static int n_mmc_protect_part = sizeof (check_mmc_protect_part) / sizeof (check_mmc_protect_part[0]);

void unlock_mmc_protect_part(void *mmaped_address)
{
  struct mmc_protect_inf *p;
  int count = 0;
  int i;

  p = convert_to_mmaped_address((void *)mmc_protect_part, mmaped_address);

  if (memcmp(p, check_mmc_protect_part, sizeof check_mmc_protect_part) != 0) {
    return;
  }

  printf("Found mmc_protect_part!\n");

  for (i = 0; i < n_mmc_protect_part; i++) {
    p[i].protect &= ~MMC_PROTECT_READ;

    switch (p[i].partition) {
    case MMC_BOOT_PARTITION:
    case MMC_RECOVERY_PARTITION:
    case MMC_SYSTEM_PARTITION:
#ifndef DISABLE_UNLOCK_MMC_WRITE
      p[i].protect &= ~MMC_PROTECT_WRITE;
#endif
      count++;
    }
  }

  printf("  %d functions are fixed to writable\n\n", count);
}
