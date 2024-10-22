package comm

type MessageType byte

type Message interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) error
	String() string
	Type() MessageType
}
