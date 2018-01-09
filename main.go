package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/beevik/etree"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	dotFile     = flag.String("dotfile", "", "dot file to write to")
	re          = regexp.MustCompile("USB\\\\VID_[0-9A-F]+&PID_[0-9]+\\\\(\\S.+)")
	ErrNotFound = errors.New("Not found")

	args []string
)

func init() {
	flag.Parse()
	if *dotFile == "" {
		fmt.Printf("must specify dot file\n")
		os.Exit(-1)
	}
	if flag.NArg() == 0 {
		fmt.Printf("At least one XML file required\n")
		os.Exit(-1)
	}
	args = flag.Args()
}

func main() {
	var sets []plugSets
	for i := range args {
		set, err := extractPlugEvents(args[i])
		if err != nil {
			fmt.Println("ERR", err)
			if err == ErrNotFound {
				continue
			}
			fmt.Println("Failed to extract events from", args[i], err)
			os.Exit(-1)
		}
		sets = append(sets, set)
	}
	if err := createGraph(sets, *dotFile); err != nil {
		fmt.Println("Failed to create graph file", err)
		os.Exit(-1)
	}
}

func extractPlugEvents(f string) (set []usbplugevent, err error) {
	var fin *os.File
	if fin, err = os.Open(f); err != nil {
		return
	}
	defer fin.Close()
	sc := bufio.NewScanner(fin)
	sc.Buffer(make([]byte, 1024*1024*32), 1024*1024*32)
	sp := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		n := strings.Index(string(data), "</Event>")
		if n == -1 && atEOF {
			advance = len(data)
			token = data
			if len(data) == 0 {
				advance = 1
			}
			return
		}
		if n != -1 {
			n = n + 8
			advance = n
			token = data[0:n]
			return
		}
		return
	}
	sc.Split(sp)
	var t string
	var upe usbplugevent
	for sc.Scan() {
		if t = strings.Trim(strings.TrimSpace(sc.Text()), "\x00"); len(t) == 0 {
			continue
		}
		if upe, err = processEvent(t); err != nil {
			if err == ErrNotFound {
				continue
			}
			fmt.Println("Failed to process Event", err)
		}
		set = append(set, upe)
	}
	if len(set) == 0 {
		err = ErrNotFound
		return
	} else {
		err = nil
	}
	return
}

func createGraph(sets []plugSets, f string) error {
	var uniques []string
	fout, err := os.Create(f)
	if err != nil {
		return err
	}
	for i := range sets {
		uniques = append(uniques, uniqueUSBs(sets[i])...)
	}

	fmt.Fprintf(fout, "digraph USBPlugs{\n")
	for _, u := range uniques {
		fmt.Fprintf(fout, "\t\"%s\" [color=Red, fontcolor=Red, shape=box]\n", u)
	}
	fmt.Fprintf(fout, "\n")

	for _, set := range sets {
		for _, s := range set {
			fmt.Fprintf(fout, "\t\"%s\" -> \"%s\";\n", s.serial, s.computer)
		}
	}
	fmt.Fprintf(fout, "}")
	if err = fout.Close(); err != nil {
		return err
	}
	return nil
}

func uniqueUSBs(set []usbplugevent) (r []string) {
	v := make(map[string]bool, 1)
	for i := range set {
		v[set[i].serial] = true
	}
	for k, _ := range v {
		r = append(r, k)
	}
	return
}

type plugSets []usbplugevent

type usbplugevent struct {
	computer string
	serial   string
}

func processEvent(t string) (p usbplugevent, err error) {
	var id uint64
	var computer string
	var e *etree.Element
	var attr *etree.Attr
	doc := etree.NewDocument()
	if err = doc.ReadFromString(t); err != nil {
		return
	}
	if e = doc.FindElement(`.//EventID`); e == nil {
		err = errors.New("no EventID element")
		return
	}
	if id, err = strconv.ParseUint(e.Text(), 10, 16); err != nil {
		return
	}
	err = ErrNotFound
	if id != 6416 {
		return
	}
	if e = doc.FindElement(`.//System//Provider`); e == nil {
		err = errors.New("no provider found in element")
		return
	} else if e.SelectAttr(`Name`).Value != `Microsoft-Windows-Security-Auditing` {
		return
	}
	if e = doc.FindElement(`.//System//Computer`); e == nil {
		err = errors.New("no computer found in element")
		return
	}
	computer = e.Text()
	for _, e = range doc.FindElements(`.//EventData//Data`) {
		if attr = e.SelectAttr(`Name`); attr == nil {
			continue
		} else if attr.Value != `DeviceId` {
			continue
		}
		if serial, ok := getUSBSerialNumber(e.Text()); ok {
			p.computer = computer
			p.serial = serial
			err = nil
			return
		}
	}
	return
}

func getUSBSerialNumber(t string) (serial string, ok bool) {
	var loc []int
	if loc = re.FindStringSubmatchIndex(t); loc == nil {
		return
	} else if len(loc) != 4 {
		return
	}
	serial = t[loc[2]:loc[3]]
	ok = true
	return
}
