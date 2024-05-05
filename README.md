# cgoleak: A ebpf based memory leak detector for CGO program

The go pprof only shows the memory which is allocated by the go-runtime, so cgo allocations
go un-noticed, which makes hard to debug cgo memeory leaks. This project aims to help developers to detect memory leaks in go program with c bindings.

## Usage

```
cgoleak is a tool to detect memory leaks in Go applications with cgo

Usage:
  cgoleak [flags]

Flags:
  -h, --help           help for cgoleak
      --interval int   interval to check for leaks (default 5)
      --path string    path to the binary
      --pid int        pid of the process
```

## How this is different from similar projects?

This program is a trimmed version of bcc's [`memleak.py`](https://github.com/iovisor/bcc/blob/master/tools/memleak.py) to fulfill the needs of the go developer.


The `memleak.py` counts both runtime allocation and cgo allocation. It can only store a fixed
number of samples. So it drops cgo samples when it doesn't meet the sampling requirements.
This makes `memleak.py` unusable for go developers usecase. 

On the flip side, cgoleak only tracks cgo allocations. This project aims to solve go developer
needs rather than being a generic memory leak detector.

## Supported Allocators

allocator| supported
-----|-----
malloc| ✅ 
jemalloc| ❌


## References

- [memleak.py](https://github.com/iovisor/bcc/blob/master/tools/memleak.py)
- [Pyroscope](https://github.com/grafana/pyroscope)
- [Parca](https://github.com/parca-dev/parca)
- [Julia Evans's Blog](https://jvns.ca/#rbspy)



