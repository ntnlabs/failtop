// sources/authlog/tailer.go
//go:build linux

package authlog

import (
	"bufio"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// TailFile tails the file at path using inotify, sending new lines to out.
// Reads from EOF on open (only new lines, not existing content).
// Stops when the done channel is closed.
func TailFile(path string, out chan<- string, done <-chan struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Seek to end so we only get new lines
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	wd, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
	if err != nil {
		return err
	}
	defer unix.InotifyRmWatch(fd, uint32(wd))

	reader := bufio.NewReader(f)
	buf := make([]byte, unix.SizeofInotifyEvent*64)

	for {
		select {
		case <-done:
			return nil
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil || n == 0 {
			return err
		}

		// Drain new lines from the file
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				if len(line) > 0 && line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				select {
				case out <- line:
				case <-done:
					return nil
				}
			}
			if err != nil {
				break
			}
		}
	}
}
