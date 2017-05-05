bpf_headers = \
	bpf/api.h

dist_headers = $(bpf_headers)
build_headers = $(dist_headers))

EXTRA_DIST += $(dist_sources) $(dist_headers)
