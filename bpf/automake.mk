bpf_sources = bpf/datapath.c
bpf_headers = \
	bpf/api.h \
	bpf/odp-bpf.h \
    bpf/ovs-p4.h \
    bpf/helpers.h \
    bpf/openvswitch.h \
    bpf/maps.h \
    bpf/parser.h \
    bpf/lookup.h \
    bpf/action.h \
    bpf/deparser.h \
    bpf/generated_headers.h

bpf_CFLAGS = $(AM_CFLAGS)
bpf_CFLAGS += -target bpf -D__NR_CPUS__=$(shell nproc) -O2 -Wall -Werror
#bpf_CFLAGS += -D__NR_CPUS__=$(shell nproc) -O2 -Wall -Werror -emit-llvm -g
bpf_CFLAGS += -I$(top_builddir)/include -I$(top_srcdir)/include

dist_sources = $(bpf_sources)
dist_headers = $(bpf_headers)
build_sources = $(dist_sources)
build_headers = $(dist_headers))
build_objects = $(patsubst %.c,%.o,$(build_sources))

bpf: $(build_objects)
bpf/%.o: $(srcdir)/bpf/%.c
	$(MKDIR_P) $(dir $@)
	@which clang >/dev/null 2>&1 || \
		(echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
	clang $(bpf_CFLAGS) -c $< -o $@

#clang $(bpf_CFLAGS) -c $< -o -| llc -march=bpf -filetype=obj -o $@
#llvm-objdump -S -no-show-raw-insn $@ > $@.objdump

EXTRA_DIST += $(dist_sources) $(dist_headers) bpf/ovs-proto.p4 bpf/compile.sh
if HAVE_BPF
dist_bpf_DATA += $(build_objects)
endif
