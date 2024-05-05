package symbol

import (
	"debug/elf"

	"github.com/go-kit/log"
	"github.com/parca-dev/parca/pkg/profile"
	"github.com/parca-dev/parca/pkg/symbol/addr2line"
	"github.com/parca-dev/parca/pkg/symbol/demangle"
	"github.com/prometheus/procfs"
)

type SymTab struct {
	procMaps  []*procfs.ProcMap
	cachedElf map[string]*elf.File
	demangler *demangle.Demangler
}

func NewSymTab(pid int) (*SymTab, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return nil, err
	}

	procMaps, err := proc.ProcMaps()
	if err != nil {
		return nil, err
	}

	demangler := demangle.NewDemangler("simple", false)

	return &SymTab{
		procMaps:  procMaps,
		cachedElf: make(map[string]*elf.File),
		demangler: demangler,
	}, nil
}

func (s *SymTab) Resolve(addr uint64) ([]profile.LocationLine, error) {
	for _, procMap := range s.procMaps {
		if procMap.Pathname == "" {
			continue
		}

		if uint64(procMap.StartAddr) <= addr && addr <= uint64(procMap.EndAddr) {
			elfFile, err := s.getElfFile(procMap.Pathname)

			liner, err := addr2line.DWARF(log.NewNopLogger(), procMap.Pathname, elfFile, s.demangler)
			if err != nil {
				return nil, err
			}

			base := s.findBase(elfFile, procMap)
			return liner.PCToLines(addr - base)
		}
	}
	return []profile.LocationLine{}, nil
}

func (c *SymTab) getElfFile(path string) (*elf.File, error) {
	elfFile, ok := c.cachedElf[path]
	if !ok {
		elfFile, err := elf.Open(path)
		if err != nil {
			return nil, err
		}
		c.cachedElf[path] = elfFile
		return elfFile, nil
	}
	return elfFile, nil
}

func (c *SymTab) findBase(elfFile *elf.File, procMap *procfs.ProcMap) uint64 {
	if elfFile.FileHeader.Type == elf.ET_EXEC {
		return 0
	}

	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X != 0) {
			if prog.Off == uint64(procMap.Offset) {
				return uint64(procMap.StartAddr) - uint64(prog.Vaddr)
			}
			alignedOffset := uint64(prog.Off) & 0xfffffffffffff000
			if alignedOffset == uint64(procMap.Offset) {
				d := prog.Off - alignedOffset
				return uint64(procMap.StartAddr) - uint64(prog.Vaddr) + d
			}
		}
	}
	return 0
}

func (c *SymTab) Close() error {
	for _, elfFile := range c.cachedElf {
		err := elfFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
