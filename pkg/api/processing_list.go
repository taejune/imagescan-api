package api

import (
	"sync"

	"github.com/opencontainers/go-digest"
)

var list *ScanningList

func init() {
	list = &ScanningList{
		entries: []digest.Digest{},
		mutex:   &sync.RWMutex{},
	}
}

type ScanningList struct {
	entries []digest.Digest
	mutex   *sync.RWMutex
}

func IsScanning(target digest.Digest) bool {
	list.mutex.RLock()
	defer list.mutex.RUnlock()

	for _, entry := range list.entries {
		if entry == target {
			return true
		}
	}
	return false
}

func AddScanning(target digest.Digest) {
	list.mutex.Lock()
	list.entries = append(list.entries, target)
	list.mutex.Unlock()
}

func RemoveScanning(target digest.Digest) {
	list.mutex.Lock()
	for i, entry := range list.entries {
		if entry == target {
			list.entries = append(list.entries[:i], list.entries[i+1:]...)
		}
	}
	list.mutex.Unlock()
}
