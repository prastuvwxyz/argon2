package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrSaltNotFound       = errors.New("salt not found")
	ErrKeyNotFound        = errors.New("key not found")
	ErrInvalidHash        = errors.New("invalid hash format")
	ErrInvalidVersion     = errors.New("argon version not supported")
	ErrInvalidMode        = errors.New("argon mode not supported")
	ErrInvalidArgonConfig = errors.New("invalid argon config")
)

const (
	SegmentsLength = 6
)

const (
	Argon2i = iota + 1
	Argon2id
)

var Mode = map[int]string{Argon2i: "argon2i", Argon2id: "argon2id"}

const (
	Version13 = 0x13
)

var Version = map[uint32]int{Version13: 13}

type Config struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
	Mode        string
	Version     int
	Salt        []byte
	Key         []byte
}

func Default() *Config {
	return &Config{
		Time:        1,
		Memory:      64 * 1024,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
		Mode:        Mode[Argon2id],
		Version:     Version[Version13],
		Salt:        nil,
		Key:         nil,
	}
}

func NewWithHash(hash string) (*Config, error) {
	c := &Config{}
	return c.decode(hash)
}

func (c *Config) SetTime(time uint32) *Config {
	c.Time = time
	return c
}

func (c *Config) SetMemory(memory uint32) *Config {
	c.Memory = memory
	return c
}

func (c *Config) SetParallelism(parallel uint8) *Config {
	c.Parallelism = parallel
	return c
}

func (c *Config) SetSaltLength(saltLength uint32) *Config {
	c.SaltLength = saltLength
	return c
}

func (c *Config) SetKeyLength(keyLength uint32) *Config {
	c.KeyLength = keyLength
	return c
}

func (c *Config) SetMode(mode string) *Config {
	c.Mode = mode
	return c
}

func (c *Config) SetVersion(version int) *Config {
	c.Version = version
	return c
}

func (c *Config) CreateHash(password string) (hash []byte, err error) {
	if c.Salt == nil {
		c.Salt, err = c.generateSalt()
		if err != nil {
			return nil, err
		}
	}

	c.Key = c.generateKey(password)
	return c.encode()
}

func (c *Config) generateSalt() (salt []byte, err error) {
	salt = make([]byte, c.SaltLength)
	_, err = rand.Read(salt)
	return salt, err
}

func (c *Config) generateKey(password string) (key []byte) {
	switch c.Mode {
	case Mode[Argon2id]:
		key = argon2.IDKey([]byte(password), c.Salt, c.Time, c.Memory, c.Parallelism, c.KeyLength)
	default:
		key = argon2.Key([]byte(password), c.Salt, c.Time, c.Memory, c.Parallelism, c.KeyLength)
	}
	return key
}

var (
	argFirst       = []byte("$")
	argVersion     = []byte("$v=")
	argMemory      = []byte("$m=")
	argTime        = []byte(",t=")
	argParallelism = []byte(",p=")
)

func (c *Config) encode() (hash []byte, err error) {
	if c.Salt == nil {
		return nil, ErrSaltNotFound
	}

	if c.Key == nil {
		return nil, ErrKeyNotFound
	}

	salt := base64.RawStdEncoding.EncodeToString(c.Salt)
	key := base64.RawStdEncoding.EncodeToString(c.Key)

	var buff bytes.Buffer
	buff.Write(argFirst)
	buff.WriteString(c.Mode)
	buff.Write(argVersion)
	buff.WriteString(strconv.FormatInt(int64(c.Version), 10))
	buff.Write(argMemory)
	buff.WriteString(strconv.FormatUint(uint64(c.Memory), 10))
	buff.Write(argTime)
	buff.WriteString(strconv.FormatUint(uint64(c.Time), 10))
	buff.Write(argParallelism)
	buff.WriteString(strconv.FormatUint(uint64(c.Parallelism), 10))
	buff.WriteByte('$')
	buff.WriteString(salt)
	buff.WriteByte('$')
	buff.WriteString(key)

	return buff.Bytes(), nil
}

func (c *Config) decode(hash string) (*Config, error) {
	segments := strings.Split(hash, "$")
	if len(segments) != SegmentsLength {
		return nil, ErrInvalidHash
	}
	c.SetMode(segments[1])

	if !(c.Mode == Mode[Argon2i] || c.Mode == Mode[Argon2id]) {
		return nil, ErrInvalidMode
	}

	_, err := fmt.Sscanf(segments[2], "v=%d", &c.Version)
	if err != nil {
		return nil, err
	}
	if c.Version != Version[Version13] {
		return nil, ErrInvalidVersion
	}

	_, err = fmt.Sscanf(segments[3], "m=%d,t=%d,p=%d", &c.Memory, &c.Time, &c.Parallelism)
	if err != nil {
		return nil, err
	}

	c.Salt, err = base64.RawStdEncoding.Strict().DecodeString(segments[4])
	if err != nil {
		return nil, err
	}
	c.SetSaltLength(uint32(len(c.Salt)))

	c.Key, err = base64.RawStdEncoding.Strict().DecodeString(segments[5])
	if err != nil {
		return nil, err
	}
	c.SetKeyLength(uint32(len(c.Key)))

	return c, nil
}

func (c *Config) Match(password string) (match bool, err error) {
	if c.Salt == nil || c.Key == nil {
		return false, ErrInvalidArgonConfig
	}

	key := c.generateKey(password)
	return subtle.ConstantTimeCompare(c.Key, key) == 1, nil
}
