bpf_headers = \
	bpf/api.h \
	bpf/odp-bpf.h

dist_headers = $(bpf_headers)
build_headers = $(dist_headers))

EXTRA_DIST += $(dist_sources) $(dist_headers)
