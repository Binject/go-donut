package main

import (
	"flag"
	"io/ioutil"
	"log"
	"strings"

	"github.com/Binject/go-donut/donut"
)

func main() {

	var srcFile, dstFile, url, archStr string
	flag.StringVar(&srcFile, "i", "", "Input file (source)")
	flag.StringVar(&url, "u", "", "Input URL (source)") // ie. file:///C:/Windows//System32//calc.exe
	flag.StringVar(&dstFile, "o", "payload.bin", "Output file (payload)")
	flag.StringVar(&archStr, "a", "x84", "Architecture: x32, x64, or x84 (x32+x64)")
	flag.Parse()

	var donutArch donut.DonutArch
	switch strings.ToLower(archStr) {
	case "x32":
		donutArch = donut.X32
	case "x64":
		donutArch = donut.X64
	case "x84":
		donutArch = donut.X84
	default:
		log.Fatal("Unknown architecture provided")
	}

	var err error
	if srcFile == "" {
		if url == "" {
			log.Fatal("No source URL or file provided")
		}
		payload, err := donut.ShellcodeFromURL(url, &donut.DonutConfig{Arch: donutArch})
		if err == nil {
			err = ioutil.WriteFile(dstFile, payload.Bytes(), 0440)
		}
	} else {
		payload, err := donut.ShellcodeFromFile(srcFile, &donut.DonutConfig{Arch: donutArch})
		if err == nil {
			err = ioutil.WriteFile(dstFile, payload.Bytes(), 0440)
		}
	}
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Done!")
	}
}
