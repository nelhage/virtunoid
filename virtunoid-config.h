/*
 * This file contains offsets for Ubuntu's
 *   qemu-kvm_0.14.0+noroms-0ubuntu4_amd64.deb
 *
 * $ sha1sum /usr/bin/kvm
 * 5b9a5d591f60ca82f7f51013284959ab2319266e  /usr/bin/kvm
 *
 * Most of these offsets will need to be updated for any new target.
 */

#define FORK                     0x407c78
#define EXECV                    0x4086a8

#define SIZEOF_RTCSTATE                  488
#define OFFSET_RTCSTATE_NEXT_SECOND_TIME 0x1b8
#define OFFSET_RTCSTATE_SECOND_TIMER     0x1d8

#define RTC_UPDATE_SECOND        0x5b2280

#define SCSI_REQ_COMPLETE        0x47cb20
#define SCSI_READ_COMPLETE       0x47b1a0
#define TARGET_RET               0x47b20d
#define MPROTECT                 0x409158

#define ISA_UNASSIGN_IOPORT      0x476920

/*
 * Dummy clock object
 * struct QEMUClock {
 *  int type = 0,
 *  int enabled = 1;
 };
 */
#define CLOCK_HVA                0x5e1924

#define CPU_OUTL                 0x476a90

#define SIZEOF_BUS_STATE        56
#define SIZEOF_SCSI_REQUEST     112
#define SIZEOF_SCSI_GENERIC_REQ 216

#define IOPORT_WRITEB_THUNK     0x4765e0
#define IOPORT_READL_THUNK      0x476590
#define QEMU_GET_RAM_PTR        0x4d99d0

#define BDRV_RW_EM_CB           0x4390b0
#define KVM_ARCH_DO_IOPERM      0x42ee60

/* &ram_list.blocks.lh_first */
#define ADDR_RAMLIST_FIRST       0x10ff318

#define E820_TABLE               0x1104400
#define SIZEOF_E820_TABLE        324
#define HPET_CFG                 0x959e20
#define SIZEOF_HPET_CFG          121

/* Offset of the ICMP data inside qemu's net queue buffer */
/* = sizeof(NetPacket) + sizeof(iphdr) + sizeof(icmphdr) + some
   other crap I've forgotten */
#define PACKET_OFFSET   74

#undef HAVE_TIMER_SCALE
