//go:build linux

package sysconf

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// getppid is os.Getppid; tests replace it.
var getppid = os.Getppid

// ParentChain lists the ancestors of this process, from the parent up to
// pid 1 (excluded), with their real uid and comm.
func ParentChain() ([]Proc, error) {
	var out []Proc
	pid := getppid()
	for pid > 1 && len(out) < 64 {
		p, ppid, err := readStatus(pid)
		if err != nil {
			return out, err
		}
		out = append(out, p)
		pid = ppid
	}
	return out, nil
}

// readStatus reads the name, real uid and parent of pid from
// /proc/<pid>/status.
func readStatus(pid int) (Proc, int, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return Proc{}, 0, err
	}
	defer f.Close()
	p := Proc{PID: pid, UID: -1}
	ppid := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			p.Comm = v
		case "PPid":
			ppid, _ = strconv.Atoi(v)
		case "Uid":
			if fields := strings.Fields(v); len(fields) > 0 {
				if uid, err := strconv.Atoi(fields[0]); err == nil {
					p.UID = uid
				}
			}
		}
	}
	return p, ppid, sc.Err()
}
