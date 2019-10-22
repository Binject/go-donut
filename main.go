package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/Binject/go-donut/donut"
)

func main() {

	var srcFile, dstFile, url, archStr string
	var noCrypto, dotNet bool

	flag.StringVar(&srcFile, "i", "", "Input file (source)")
	flag.StringVar(&url, "u", "", "Input URL (source)") // ie. file:///C:/Windows//System32//calc.exe
	flag.StringVar(&dstFile, "o", "payload.bin", "Output file (payload)")
	flag.StringVar(&archStr, "a", "x84", "Architecture: x32, x64, or x84 (x32+x64)")
	flag.BoolVar(&dotNet, "dotnet", false, ".NET Mode, set true for .NET exe and DLL files (autodetect not implemented)")
	flag.BoolVar(&noCrypto, "nocrypto", false, "UNSAFE! Disables all crypto and randomness for testing only")
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

	config := new(donut.DonutConfig)
	config.Arch = donutArch
	config.NoCrypto = noCrypto
	config.InstType = donut.DONUT_INSTANCE_PIC //todo: add URL CLI options
	config.DotNetMode = dotNet

	var err error
	if srcFile == "" {
		if url == "" {
			log.Fatal("No source URL or file provided")
		}
		payload, err := donut.ShellcodeFromURL(url, config)
		if err == nil {
			err = ioutil.WriteFile(dstFile, payload.Bytes(), 0644)
		}
	} else {
		payload, err := donut.ShellcodeFromFile(srcFile, config)
		if err == nil {
			f, err := os.Create(dstFile)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			if _, err = payload.WriteTo(f); err != nil {
				log.Fatal(err)
			}
		}
	}
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Done!")
	}
}
