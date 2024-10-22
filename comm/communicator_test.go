package comm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setup(t *testing.T, handleMessage func([]byte)) []*Communicator {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../data")

	ports := []string{"10001", "10002", "10003"}
	cfgs := prepareTest(dir, ports)

	cs := []*Communicator{}
	for _, cfg := range cfgs {
		c, err := NewCommunicator(cfg, handleMessage)
		assert.NoError(t, err)
		cs = append(cs, c)
	}

	return cs
}

func TestConn(t *testing.T) {
	cs := setup(t, func(d []byte) {
		fmt.Printf("PRINT msg: %s\n", string(d))
	})

	for _, c := range cs {
		c.Start()
	}

	time.Sleep(100 * time.Second)

	for _, c := range cs {
		c.Close()
	}
}
