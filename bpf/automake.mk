bpf_sources = bpf/datapath.c
bpf_headers = \
	bpf/api.h \
	bpf/odp-bpf.h

bpf_CFLAGS = $(AM_CFLAGS)
bpf_CFLAGS += -target bpf -D__NR_CPUS__=$(shell nproc) -O2 -Wall -Werror
bpf_CFLAGS += -I$(top_builddir)/include -I$(top_srcdir)/include

dist_sources = $(bpf_sources)
dist_headers = $(bpf_headers)
build_sources = $(dist_sources)
build_headers = $(dist_headers))
build_objects = $(patsubst %.c,%.o,$(build_sources))

bpf/datapath.o: $(srcdir)/bpf/datapath.c
	$(MKDIR_P) $(dir $@)
	@which clang >/dev/null 2>&1 || \
		(echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
	clang $(bpf_CFLAGS) -c $< -o $@

EXTRA_DIST += $(dist_sources) $(dist_headers)
if HAVE_BPF
dist_bpf_DATA += $(build_objects)
endif
