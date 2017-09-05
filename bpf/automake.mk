bpf_headers = \
	bpf/api.h \
	bpf/generated_headers.h \
	bpf/odp-bpf.h
bpf_extra = \
	bpf/compile.sh \
	bpf/ovs-proto.p4

dist_headers = $(bpf_headers)
build_headers = $(dist_headers))

EXTRA_DIST += $(dist_sources) $(dist_headers) $(bpf_extra)
