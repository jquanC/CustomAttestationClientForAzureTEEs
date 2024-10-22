package comm

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPeer(t *testing.T) {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../data")

	cfgs := prepareTest(dir, []string{"8444", "8445"})
	srvCfg := cfgs[0]
	clientCfg := cfgs[1]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msgCh := make(chan []byte, MsgChanSize)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case data := <-msgCh:
				myMsg := &MyMessage{}

				err := myMsg.Deserialize(data)
				if err != nil {
					fmt.Printf("PRINT msg: %s\n", string(data))
				} else {
					fmt.Printf("PRINT msg: %s\n", myMsg.String())
				}
			}
		}
	}()

	srvHandleConn := func(ctx context.Context, conn net.Conn) {
		peer := NewPeer(ctx, clientCfg.Name, conn, msgCh)
		defer peer.Close()

		wg1 := sync.WaitGroup{}
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			peer.Listen()
		}()

		time.Sleep(1 * time.Second)

		if err := peer.Ping(); err != nil {
			fmt.Printf("srvHandleConn: ping err: %v\n", err)
		}

		if _, err = peer.Send(&MyMessage{
			MsgType:  MsgTypeCustom,
			From:     conn.LocalAddr().String(),
			To:       conn.RemoteAddr().String(),
			Data:     []byte("1000"),
			CreateAt: time.Now(),
		}); err != nil {
			fmt.Printf("srvHandleConn: send msg err: %v\n", err)
		}

		wg1.Wait()
	}

	srv := NewServer(ctx, srvCfg, srvHandleConn)
	go srv.Listen()

	time.Sleep(1 * time.Second)

	clientHandleConn := func(ctx context.Context, conn net.Conn) {
		peer := NewPeer(ctx, srvCfg.Name, conn, msgCh)
		defer peer.Close()

		wg2 := sync.WaitGroup{}

		wg2.Add(1)
		go func() {
			defer wg2.Done()
			peer.Listen()
		}()

		time.Sleep(1 * time.Second)

		if err := peer.Ping(); err != nil {
			fmt.Printf("clientHandleConn: ping err: %v\n", err)
		}

		if _, err := peer.Send(&MyMessage{
			MsgType:  MsgTypeCustom,
			From:     conn.LocalAddr().String(),
			To:       conn.RemoteAddr().String(),
			Data:     []byte("1"),
			CreateAt: time.Now(),
		}); err != nil {
			fmt.Printf("clientHandleConn: send msg err: %v\n", err)
		}

		wg2.Wait()
	}

	dial(
		ctx,
		clientCfg.ClientCert, clientCfg.ClientKey, srvCfg.CACert, srvCfg.Address,
		clientHandleConn, &wg,
	)

	time.Sleep(5 * time.Second)

	cancel()

	wg.Wait()
	srv.Close()
}
