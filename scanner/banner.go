package scanner

import (
	"bufio"
	"net"
	"time"
)

func GrabBanner(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)
	buffer := make([]byte, 1024)
	n, err := reader.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}
