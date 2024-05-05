LIBBPF_VERSION=0.6.1
LIBBPF_PREFIX="https://raw.githubusercontent.com/libbpf/libbpf/v$(LIBBPF_VERSION)"

.PHONY: get-headers
get-headers: get-libbpf-headers

.PHONY: get-libbpf-headers
get-libbpf-headers:
	cd libbpf && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_endian.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_helper_defs.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_helpers.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_tracing.h && \
		curl -O $(LIBBPF_PREFIX)/src/bpf_core_read.h

.PHONY: clean
clean:
	rm -rf libbpf/*.h
