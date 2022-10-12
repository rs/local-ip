package localip

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

type Cache interface {
	Get(key string) ([]byte, error)
	Put(key string, payload []byte) error
}

type FileCache string

func (c FileCache) Get(key string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(string(c), key))
}

func (c FileCache) Put(key string, payload []byte) error {
	_ = os.MkdirAll(string(c), 0700)
	return ioutil.WriteFile(filepath.Join(string(c), key), payload, 0600)
}
