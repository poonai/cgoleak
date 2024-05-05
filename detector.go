package cgoleak

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
	"github.com/parca-dev/parca/pkg/profile"
	"github.com/poonai/cgoleak/sampler"
	"github.com/poonai/cgoleak/symbol"
)

type Detector struct {
	sampler *sampler.Sampler
	symTab  *symbol.SymTab
}

func NewDetector(pid int) (*Detector, error) {
	binPath, err := execPath(pid)
	if err != nil {
		return nil, err
	}

	s, err := sampler.NewSampler(binPath, pid)
	if err != nil {
		return nil, err
	}
	symTab, err := symbol.NewSymTab(pid)
	if err != nil {
		return nil, err
	}

	return &Detector{sampler: s, symTab: symTab}, nil
}

func (d *Detector) DumpAllocs(ctx context.Context, interval time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			sizez, traces := d.allocs()
			d.prettyPrint(sizez, traces)
		}
	}
}

func (d *Detector) allocs() ([]int, [][]profile.LocationLine) {
	samples := d.sampler.Samples()

	var sizes []int
	var traces [][]profile.LocationLine
	for _, sample := range samples {
		trace := []profile.LocationLine{}
		for _, stackPtr := range sample.Stack {
			lines, err := d.symTab.Resolve(stackPtr)
			if err != nil {
				continue
			}
			trace = append(trace, lines...)
		}

		sizes = append(sizes, int(sample.TotalSize))
		traces = append(traces, trace)
	}

	return sizes, traces
}

func (d *Detector) prettyPrint(sizes []int, traces [][]profile.LocationLine) {
	tab := tablewriter.NewWriter(os.Stdout)
	tab.SetRowSeparator("-")
	tab.SetCenterSeparator("*")
	tab.SetRowLine(true)
	tab.SetHeader([]string{"Size", "Stack Trace"})

	for i, trace := range traces {
		var traceStr string
		for _, t := range trace {
			traceStr += fmt.Sprintf("%s\n", t.Function.Name)
		}
		tab.Append([]string{humanize.Bytes(uint64(sizes[i])), traceStr})
	}

	tab.Render()
}

func (d *Detector) Close() error {
	d.symTab.Close()
	return d.sampler.Close()
}

func execPath(pid int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if os.IsNotExist(err) {
		return "", nil
	}
	if os.Stat(path); err != nil {
		return "", err
	}
	return path, err
}
