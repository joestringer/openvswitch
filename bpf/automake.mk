bpf_sources = bpf/datapath.c
bpf_cilium_headers = \
	bpf/api.h \
	bpf/bpf_features.h \
	bpf/common.h \
	bpf/conntrack.h \
	bpf/csum.h \
	bpf/ipv4.h \
	bpf/ipv6.h \
	bpf/l4.h \
	bpf/utils.h
bpf_headers = \
	bpf/datapath.h \
	bpf/odp-bpf.h \
	bpf/ovs-p4.h \
	bpf/helpers.h \
	bpf/openvswitch.h \
	bpf/maps.h \
	bpf/parser.h \
	bpf/lookup.h \
	bpf/action.h \
	bpf/deparser.h \
	bpf/generated_headers.h \
	$(bpf_cilium_headers)
bpf_extra = \
	bpf/compile.sh \
	bpf/ovs-proto.p4

dist_headers = $(bpf_headers)
build_headers = $(dist_headers))

EXTRA_DIST += $(dist_sources) $(dist_headers) $(bpf_extra)
