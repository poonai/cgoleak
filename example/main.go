package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/DataDog/zstd"
)

func main() {
	for {
		buf := &bytes.Buffer{}
		writer := zstd.NewWriter(buf)

		for i := 0; i < 100; i++ {
			_, err := writer.Write([]byte("hello world"))
			if err != nil {
				log.Fatal(err)
			}
		}

		writer.Flush()
		//writer.Close()

		reader := zstd.NewReader(buf)
		for {
			b := make([]byte, 1)
			_, err := reader.Read(b)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}

			if err == io.EOF {
				break
			}
		}
		fmt.Println("done")
		//reader.Close()
		time.Sleep(time.Second * 4)
	}
}
