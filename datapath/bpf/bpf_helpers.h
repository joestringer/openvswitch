#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;
static void *(*bpf_fetch_ptr)(void *unsafe_ptr) =
	(void *) BPF_FUNC_fetch_ptr;
static unsigned long long (*bpf_fetch_u64)(void *unsafe_ptr) =
	(void *) BPF_FUNC_fetch_u64;
static unsigned int (*bpf_fetch_u32)(void *unsafe_ptr) =
	(void *) BPF_FUNC_fetch_u32;
static unsigned short (*bpf_fetch_u16)(void *unsafe_ptr) =
	(void *) BPF_FUNC_fetch_u16;
static unsigned char (*bpf_fetch_u8)(void *unsafe_ptr) =
	(void *) BPF_FUNC_fetch_u8;
static int (*bpf_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_printk;
static int (*bpf_memcmp)(void *unsafe_ptr, void *safe_ptr, int size) =
	(void *) BPF_FUNC_memcmp;
static void (*bpf_dump_stack)(void) =
	(void *) BPF_FUNC_dump_stack;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static void *(*bpf_get_current)(void) =
	(void *) BPF_FUNC_get_current;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};

#endif
