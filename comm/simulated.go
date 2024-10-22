package comm

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"path/filepath"
	"time"
)

const (
	MsgTypePing   MessageType = 0x01
	MsgTypePong   MessageType = 0x02
	MsgTypeCustom MessageType = 0x03
)

type MyMessage struct {
	MsgType  MessageType
	Data     []byte
	From     string
	To       string
	CreateAt time.Time
}

func (m *MyMessage) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *MyMessage) String() string {
	return fmt.Sprintf("type=%s, from=%s, to=%s, createdAt=%v, data=0x%x", msgType(m.MsgType), m.From, m.To, m.CreateAt.Unix(), m.Data)
}

func (m *MyMessage) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(m); err != nil {
		return err
	}

	return nil
}

func (m *MyMessage) Type() MessageType {
	return MessageType(m.MsgType)
}

func msgType(t MessageType) string {
	switch t {
	case MsgTypePing:
		return "Ping"
	case MsgTypePong:
		return "Pong"
	case MsgTypeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

func prepareTest(dir string, ports []string) []*Config {
	names := []string{}
	addresses := []string{}
	serverCertFiles := []string{}
	serverKeyFiles := []string{}
	clientCertFiles := []string{}
	clientKeyFiles := []string{}
	CACertFiles := []string{}
	for i, port := range ports {
		addresses = append(addresses, "localhost:"+port)
		names = append(names, "node"+fmt.Sprintf("%d", i+1))
		serverCertFiles = append(serverCertFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i+1)+"-server.crt"))
		serverKeyFiles = append(serverKeyFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i+1)+"-server.key"))
		clientCertFiles = append(clientCertFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i+1)+"-client.crt"))
		clientKeyFiles = append(clientKeyFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i+1)+"-client.key"))
		CACertFiles = append(CACertFiles, filepath.Join(dir, "node"+fmt.Sprintf("%d", i+1)+"-ca.crt"))
	}

	cfgs := []*Config{}
	for i := 0; i < len(ports); i++ {
		cfg := &Config{
			Name:       names[i],
			Address:    addresses[i],
			ServerCert: serverCertFiles[i],
			ServerKey:  serverKeyFiles[i],
			ClientCert: clientCertFiles[i],
			ClientKey:  clientKeyFiles[i],
			CACert:     CACertFiles[i],
		}
		cfg.Peers = []PeerConfig{}
		for j := 0; j < len(ports); j++ {
			if i == j {
				continue
			}
			cfg.Peers = append(cfg.Peers, PeerConfig{
				Name:    names[j],
				Address: addresses[j],
				CACert:  CACertFiles[j],
			})
		}
		cfgs = append(cfgs, cfg)
	}

	return cfgs
}
