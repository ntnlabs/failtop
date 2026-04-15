// sources/authlog/journald.go
package authlog

import (
	"bufio"
	"os/exec"
)

// TailJournald runs `journalctl -f -u sshd --output=short` and sends lines to out.
// Blocks until the done channel is closed or journalctl exits.
func TailJournald(out chan<- string, done <-chan struct{}) error {
	cmd := exec.Command("journalctl", "-f", "-u", "sshd", "--output=short", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		<-done
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		select {
		case out <- line:
		case <-done:
			return nil
		}
	}
	return cmd.Wait()
}
