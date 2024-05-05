package sampler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/u-root/mkuimage/ldd"
)

type Sampler struct {
	EbpfObj samplerObjects
	probes  []link.Link
}

type Hook struct {
	Lib  string
	Func string
	Prog *ebpf.Program
	Uret bool
}

func NewSampler(binPath string, pid int) (*Sampler, error) {

	var obj samplerObjects
	if err := loadSamplerObjects(&obj, nil); err != nil {
		return nil, err
	}

	loadedLibs, err := ldd.List(binPath)
	if err != nil {
		return nil, err
	}

	hooks := []Hook{{
		Lib:  "libc",
		Func: "malloc",
		Prog: obj.MallocEnter,
	}, {
		Lib:  "libc",
		Func: "malloc",
		Prog: obj.MallocExit,
		Uret: true,
	}, {
		Lib:  "libc",
		Func: "free",
		Prog: obj.FreeEnter,
	},
	//... add other hooks like jemalloc, tcmalloc, etc.
	}

	var probes []link.Link
	for _, lib := range loadedLibs {
		for _, hook := range hooks {
			if !strings.Contains(lib, hook.Lib) {
				continue
			}
			execLink, err := link.OpenExecutable(lib)
			if err != nil {
				return nil, err
			}

			if hook.Uret {
				probe, err := execLink.Uretprobe(hook.Func, hook.Prog, &link.UprobeOptions{
					PID: pid,
				})
				if err != nil {
					return nil, err
				}
				probes = append(probes, probe)
				continue
			}
			probe, err := execLink.Uprobe(hook.Func, hook.Prog, &link.UprobeOptions{
				PID: pid,
			})
			if err != nil {
				return nil, err
			}
			probes = append(probes, probe)
		}
	}

	if len(probes) == 0 {
		obj.Close()
		return nil, fmt.Errorf("no probes to attach")
	}

	return &Sampler{EbpfObj: obj, probes: probes}, nil
}

type Sample struct {
	Stack     []uint64
	TotalSize uint64
}

func (s *Sampler) Samples() (samples []Sample) {
	itr := s.EbpfObj.TotalAllocs.Iterate()

	var stackID uint32
	var size uint64
	for itr.Next(&stackID, &size) {
		stack, err := s.getStack(stackID)
		if err != nil {
			continue
		}
		samples = append(samples, Sample{Stack: stack, TotalSize: size})
	}
	return samples
}

func (s *Sampler) getStack(stackID uint32) ([]uint64, error) {
	stackBuf, err := s.EbpfObj.Stacks.LookupBytes(stackID)
	if err != nil {
		return nil, err
	}

	var stack []uint64
	for i := 0; i < 127; i++ {
		var stackPtr uint64
		stackPtr = binary.LittleEndian.Uint64(stackBuf[i*8 : i*8+8])
		if stackPtr == 0 {
			continue
		}

		stack = append(stack, stackPtr)
	}
	return stack, nil
}

func (s *Sampler) Close() error {
	for _, probe := range s.probes {
		probe.Close()
	}
	return s.EbpfObj.Close()
}
