package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zzGHzz/tls-node/logger"
)

var (
	FreqToPing  = 5 * time.Second
	MsgChanSize = 100

	ErrPeerNotFound = errors.New("peer not found")
)

// Communicator is the main struct that handles the communications between nodes
type Communicator struct {
	cfg *Config

	ctx    context.Context
	cancel context.CancelFunc

	clientCert  *tls.Certificate
	peerCACerts map[string][]byte
	peerInfo    map[string]*PeerConfig

	srv   *Server
	peers map[string]*Peer
	mu    sync.Mutex

	msgCh         chan []byte
	handleMessage func([]byte)

	logger *slog.Logger
	wg     sync.WaitGroup
}

func NewCommunicator(
	cfg *Config,
	handleMessage func([]byte),
) (*Communicator, error) {
	peerInfo := make(map[string]*PeerConfig)
	for _, peer := range cfg.Peers {
		peerInfo[peer.Name] = &peer
	}

	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, err
	}

	peerCACerts := make(map[string][]byte)
	for _, peer := range cfg.Peers {
		peerCACert, err := os.ReadFile(peer.CACert)
		if err != nil {
			return nil, err
		}
		peerCACerts[peer.Name] = peerCACert
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Communicator{
		cfg:           cfg,
		ctx:           ctx,
		cancel:        cancel,
		clientCert:    &cert,
		peerCACerts:   peerCACerts,
		peerInfo:      peerInfo,
		peers:         make(map[string]*Peer),
		handleMessage: handleMessage,
		msgCh:         make(chan []byte, MsgChanSize),
		logger:        logger.New(slog.LevelDebug).With("communicator", cfg.Name),
	}, nil
}

func (c *Communicator) Close() {
	defer c.logger.Info("Stopped communicator")

	c.cancel()

	for _, peer := range c.peers {
		if peer != nil {
			peer.Close()
		}
	}

	if c.srv != nil {
		c.srv.Close()
	}

	c.wg.Wait()
}

func (c *Communicator) SelfName() string {
	return c.cfg.Name
}

func (c *Communicator) PeerNames() []string {
	var names []string
	for _, peer := range c.cfg.Peers {
		names = append(names, peer.Name)
	}
	return names
}

func (c *Communicator) Start() error {
	c.logger.Info("Starting communicator")

	// start the server
	c.srv = NewServer(c.ctx, c.cfg, c.handleConn)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.srv.Listen()
	}()

	// start the heartbeat loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.heartbeatLoop()
	}()

	// start the message handler loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleMessageLoop()
	}()

	return nil
}

// SetPeer adds a new peer to the list of connected peers. It is thread-safe.
func (c *Communicator) SetPeer(name string, conn net.Conn) bool {
	defer c.mu.Unlock()
	c.mu.Lock()

	if peer, ok := c.peers[name]; ok && peer != nil {
		return false
	}

	c.peers[name] = NewPeer(c.ctx, name, conn, c.msgCh)

	return true
}

// GetPeer gets the peer from the list of connected peers by name.
// It is thread-safe.
func (c *Communicator) GetPeer(name string) *Peer {
	defer c.mu.Unlock()
	c.mu.Lock()

	peer, ok := c.peers[name]
	if !ok {
		return nil
	}

	return peer
}

// RemovePeer removes the peer with the given name from the list of connected peers.
// It is thread-safe.
func (c *Communicator) RemovePeer(name string) {
	defer c.mu.Unlock()
	c.mu.Lock()

	delete(c.peers, name)
}

// heartbeatLoop periodically pings all connected peers to check if they are still alive.
// If a peer is not reachable, it will be removed from the list of connected peers and
// try to reconnect the peer.
func (c *Communicator) heartbeatLoop() {
	c.logger.Info("Starting heartbeat loop")
	defer c.logger.Info("Stopped heartbeat loop")

	peerNames := c.PeerNames()

	tickerPing := time.NewTicker(FreqToPing)
	defer tickerPing.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tickerPing.C:
			for _, name := range peerNames {
				peer := c.GetPeer(name)
				if peer == nil { // peer does not exist, try to reconnect
					conn, err := c.dial(name)
					if err != nil {
						c.logger.With("func", "heartbeatLoop").Error("failed to dial", slog.String("peer", name), slog.String("err", err.Error()))
						continue
					}

					// send name to the peer
					if _, err := conn.Write([]byte(c.cfg.Name)); err != nil {
						c.logger.With("func", "heartbeatLoop").Error("failed to send name to peer", slog.String("peer", name), slog.String("err", err.Error()))
						conn.Close()
						continue
					}

					if !c.SetPeer(name, conn) {
						c.logger.With("func", "hearbeatLoop").Debug("failed to set peer, closing connection", slog.String("name", name))
						conn.Close()
						continue
					}

					c.wg.Add(1)
					go func() {
						defer c.wg.Done()
						if peer := c.GetPeer(name); peer != nil {
							peer.Listen()
						}
					}()
				} else { // peer exists, ping it
					if err := peer.Ping(); err != nil { // if fail, remove the peer
						c.logger.With("func", "hearbeatLoop").Error("failed to ping", slog.String("target", name), slog.String("err", err.Error()))
						peer.Close()
						c.RemovePeer(name)
					}
				}
			}
		}
	}
}

func (c *Communicator) handleConn(ctx context.Context, conn net.Conn) {
	// receive the peer name
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		c.logger.With("func", "handleConn").Error("failed to read peer name, closing connection", slog.String("err", err.Error()))
		conn.Close()
		return
	}
	name := string(buf[:n])

	// set the peer
	if !c.SetPeer(name, conn) {
		c.logger.With("func", "handleConn").Debug("failed to set peer, closing connection", slog.String("peer", name))
		conn.Close()
		return
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if peer := c.GetPeer(name); peer != nil {
			peer.Listen()
		}
	}()
}

func (c *Communicator) handleMessageLoop() {
	c.logger.Info("Starting message handler loop")
	defer c.logger.Info("Stopped message handler loop")

	for {
		select {
		case <-c.ctx.Done():
			return
		case msg := <-c.msgCh:
			c.handleMessage(msg)
		}
	}
}

func (c *Communicator) dial(peerName string) (net.Conn, error) {
	info := c.peerInfo[peerName]
	if info == nil {
		return nil, ErrPeerNotFound
	}

	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM(c.peerCACerts[peerName])
	tlsConfig := &tls.Config{
		RootCAs:      CACertPool,
		Certificates: []tls.Certificate{*c.clientCert},
	}

	conn, err := tls.Dial("tcp", info.Address, tlsConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *Communicator) Broadcast(msg Message) error {
	for _, peer := range c.peers {
		c.logger.With("action", "broadcast").Debug("sending mesage", slog.String("to", peer.name), slog.String("msg", msg.String()))
		if _, err := peer.Send(msg); err != nil {
			return err
		}
	}
	return nil
}
