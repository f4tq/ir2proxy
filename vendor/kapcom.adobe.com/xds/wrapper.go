package xds

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/ugorji/go/codec"
	"gopkg.in/inconshreveable/log15.v2"
)

type (
	Wrapper interface {
		// Read accepts a function that is expected to do read-only operations
		// on the proto.Message, and receives a copy of the metadata possibly
		// written to in Write
		Read(func(proto.Message, interface{}))
		// Write accepts a function that may or may not update the proto.Message
		// (indicated by the return value), and a pointer to storage space for
		// associated metadata of any type
		Write(func(proto.Message, *interface{}) bool)
		// BytesAndVersion atomically sets the protobuf bytes and version string
		BytesAndVersion(log15.Logger, *[]byte, *string) bool
		Version(log15.Logger) string
		// If the receiver's proto.Message and the input proto.Message are not
		// equal: replaces the receiver's proto.Message and return true
		CompareAndReplace(log15.Logger, proto.Message) bool
		Valid() bool
		SetValid(bool)
	}

	wrapperImpl struct {
		lock    sync.RWMutex
		msg     proto.Message
		meta    interface{}
		version string
		valid   bool
	}
)

// Create a new Wrapper. If meta pointers are provided only the first is used
func NewWrapper(msg proto.Message, metas ...interface{}) Wrapper {
	var meta interface{}
	if len(metas) > 0 {
		meta = metas[0]
	}

	return &wrapperImpl{
		// lock zero-val
		msg:   msg,
		meta:  meta,
		valid: true,
	}
}

func (recv *wrapperImpl) Read(f func(proto.Message, interface{})) {
	recv.lock.RLock()
	f(recv.msg, recv.meta)
	recv.lock.RUnlock()
}

func (recv *wrapperImpl) Write(f func(proto.Message, *interface{}) bool) {
	recv.lock.Lock()

	if f(recv.msg, &recv.meta) {
		recv.version = ""
	}

	recv.lock.Unlock()
}

func (recv *wrapperImpl) BytesAndVersion(log log15.Logger, protoBytes *[]byte, version *string) (success bool) {
	recv.lock.Lock()
	defer recv.lock.Unlock()

	var err error
	*protoBytes, err = proto.Marshal(recv.msg)
	if err != nil {
		log.Error("proto.Marshal", "Error", err)
		return
	}

	hdl := new(codec.MsgpackHandle)
	hdl.WriterBufferSize = 1024
	hdl.Canonical = true

	var buf bytes.Buffer

	err = codec.NewEncoder(&buf, hdl).Encode(recv.msg)
	if err != nil {
		log.Error("encoder.Encode", "Error", err)
		return
	}

	versionArray := sha1.Sum(buf.Bytes())
	recv.version = hex.EncodeToString(versionArray[:])
	*version = recv.version

	success = true
	return
}

func (recv *wrapperImpl) Version(log log15.Logger) (version string) {
	recv.lock.RLock()
	if recv.version != "" {
		version = recv.version
		recv.lock.RUnlock()
		return
	}
	recv.lock.RUnlock()

	// cache miss. acquire a write lock

	recv.lock.Lock()
	defer recv.lock.Unlock()

	// Multiple readers could be at recv.lock.Lock()
	// Check condition again
	if recv.version != "" {
		version = recv.version
		return
	}

	hdl := new(codec.MsgpackHandle)
	hdl.WriterBufferSize = 1024
	hdl.Canonical = true

	var buf bytes.Buffer

	err := codec.NewEncoder(&buf, hdl).Encode(recv.msg)
	if err != nil {
		log.Error("encoder.Encode", "Error", err)
		return
	}

	versionArray := sha1.Sum(buf.Bytes())
	recv.version = hex.EncodeToString(versionArray[:])
	version = recv.version
	return
}

func (recv *wrapperImpl) CompareAndReplace(log log15.Logger, msg proto.Message) (protoChanged bool) {

	recv.lock.Lock()
	defer recv.lock.Unlock()

	if !proto.Equal(recv.msg, msg) {
		recv.msg = msg
		recv.version = ""
		protoChanged = true
	}

	return
}

func (recv *wrapperImpl) Valid() (valid bool) {
	recv.lock.RLock()
	valid = recv.valid
	recv.lock.RUnlock()
	return
}

func (recv *wrapperImpl) SetValid(valid bool) {
	recv.lock.Lock()
	recv.valid = valid
	recv.lock.Unlock()
}
