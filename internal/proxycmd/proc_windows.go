//go:build windows

package proxycmd

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// detachedProcess starts a console program without a console: it cannot
// read the console's input or prompt there.
const detachedProcess = 0x00000008

// start runs cmd without the console's console, in a process group of its
// own, inside a job object that kill terminates: the command and every
// process it started (ssh's children, a docker CLI plugin, ...) end
// together, and with the console itself, which holds the only handle to the
// job. The command starts suspended and runs only once it is in the job, so
// no process it starts escapes it.
func start(cmd *exec.Cmd) (kill func(), err error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	pid := uint32(cmd.Process.Pid)
	if err := assign(job, pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		windows.CloseHandle(job)
		return nil, err
	}
	if err := resume(pid); err != nil {
		windows.TerminateJobObject(job, 1)
		cmd.Wait()
		windows.CloseHandle(job)
		return nil, err
	}
	return func() {
		windows.TerminateJobObject(job, 1)
		windows.CloseHandle(job)
	}, nil
}

// assign puts the process pid in job.
func assign(job windows.Handle, pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}

// resume resumes the threads of the suspended process pid.
func resume(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return err
		}
		_, err = windows.ResumeThread(th)
		windows.CloseHandle(th)
		if err != nil {
			return err
		}
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return err
	}
	return nil
}
