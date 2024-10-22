package comm

type Config struct {
	Name    string
	Address string // host:port

	ServerCert string
	ServerKey  string

	ClientCert string
	ClientKey  string

	CACert string

	Peers []PeerConfig
}

type PeerConfig struct {
	Name    string
	Address string // host:port
	CACert  string
}
