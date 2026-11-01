//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// giveBack gives uid:gid the directories and regular files of dir, dir
// included, that the console account (uid svc) owns; it runs as root, in
// the launcher's root container for doctor --fix. The agent's account may
// write the project: nothing it puts there may redirect a chown. So dir is
// opened once, checked to be the directory it was (no link), and read only
// through that handle (os.Root: no path leads out of it); each entry is
// opened without following a link and changed through its handle (fchown),
// only when that handle is a directory, or a regular file with no other
// name (a hard link to a file elsewhere would give that file away).
// Children go before their directory, which keeps them out of the agent's
// reach while they change. Anything else is left as it is.
func giveBack(dir string, svc, uid, gid int) error {
	parent, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	base := filepath.Base(dir)
	want, err := parent.Lstat(base)
	if err != nil {
		return err
	}
	if !want.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link?): not changed", dir)
	}
	r, err := parent.OpenRoot(base)
	if err != nil {
		return err
	}
	defer r.Close()
	if got, err := r.Stat("."); err != nil || !os.SameFile(want, got) {
		return fmt.Errorf("%s changed while doctor read it: not changed", dir)
	}
	var names []string
	err = fs.WalkDir(r.FS(), ".", func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() || de.Type().IsRegular() {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	var errs []error
	for i := len(names) - 1; i >= 0; i-- {
		if err := giveBackOne(r, names[i], svc, uid, gid); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Join(dir, names[i]), err))
		}
	}
	return errors.Join(errs...)
}

// giveBackOne gives uid:gid the entry name of r when svc owns it.
func giveBackOne(r *os.Root, name string, svc, uid, gid int) error {
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != svc {
		return nil // not the console account's: left as it is
	}
	if !fi.IsDir() && (!fi.Mode().IsRegular() || st.Nlink != 1) {
		return errors.New("a hard link or not a regular file: not changed")
	}
	return f.Chown(uid, gid)
}
