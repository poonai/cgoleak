package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/poonai/cgoleak"
	"github.com/spf13/cobra"
)

var binPath string
var pid int
var interval int

var cmd = &cobra.Command{
	Use:   "cgoleak",
	Short: "cgoleak is a tool to detect memory leaks in Go applications with cgo",
	RunE: func(cmd *cobra.Command, args []string) error {
		if pid == 0 && binPath == "" {
			return fmt.Errorf("either pid or path is required")
		}
		return run()
	},
}

func init() {
	cmd.Flags().StringVar(&binPath, "path", "", "path to the binary")
	cmd.Flags().IntVar(&pid, "pid", 0, "pid of the process")
	cmd.Flags().IntVar(&interval, "interval", 5, "interval to check for leaks")
}

func run() error {

	// only supported in linux
	if runtime.GOOS != "linux" {
		return fmt.Errorf("only supported in linux")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("try with sudo. failed to remove memlock rlimit: %w.", err)
	}

	if pid == 0 {
		cmd := exec.Command(binPath)
		cmd.Stdout = os.Stdout
		go func() {
			if err := cmd.Run(); err != nil {
				log.Fatal(err)
			}
		}()

		time.Sleep(time.Second * 2)
		pid = cmd.Process.Pid
	}

	detector, err := cgoleak.NewDetector(pid)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	go func() {
		wg.Add(1)
		defer wg.Done()
		detector.DumpAllocs(ctx, time.Second*time.Duration(interval))
	}()

	// wait for signal
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	fmt.Println("Received signal, exiting program..")
	cancel()
	wg.Wait()
	return nil
}

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
