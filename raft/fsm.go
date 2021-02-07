package raft

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nodece/casbin-hraft-dispatcher/command"
	"google.golang.org/protobuf/proto"

	"github.com/pkg/errors"

	bolt "go.etcd.io/bbolt"

	"io"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/hashicorp/raft"
	"go.uber.org/zap"
)

const (
	databaseFilename = "fsm.db"
)

var (
	policyBucketName = []byte("policy_rules")
)

// FSM is state storage.
type FSM struct {
	enforcer      casbin.IDistributedEnforcer
	shouldPersist func() bool
	mutex         *sync.RWMutex
	logger        *zap.Logger
	db            *bolt.DB
	path          string
}

// NewFSM returns a FSM.
func NewFSM(path string, enforcer casbin.IDistributedEnforcer) (*FSM, error) {
	f := &FSM{
		enforcer:      enforcer,
		logger:        zap.NewExample(),
		mutex:         &sync.RWMutex{},
		shouldPersist: func() bool { return false },
		path:          path,
	}

	dbPath := filepath.Join(path, databaseFilename)
	if err := f.openDBFile(dbPath); err != nil {
		return nil, errors.Wrapf(err, "failed to open bolt file")
	}

	err := f.loadPolicy()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load policy")
	}
	return f, err
}

// openDBFile opens a bolt database by given the dbPath.
func (f *FSM) openDBFile(dbPath string) error {
	if len(dbPath) == 0 {
		return errors.New("dbPath cannot be an empty")
	}

	boltDB, err := bolt.Open(dbPath, 0666, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}

	f.db = boltDB

	return f.CreateBucket(policyBucketName)
}

// Apply applies log from raft.
func (f *FSM) Apply(log *raft.Log) interface{} {
	var cmd command.Command
	err := proto.Unmarshal(log.Data, &cmd)
	if err != nil {
		f.logger.Error("cannot to unmarshal the command", zap.Error(err), zap.ByteString("command", log.Data))
		return err
	}
	switch cmd.Type {
	case command.Command_COMMAND_TYPE_ADD:
		var request command.AddPolicyRequest
		err := proto.Unmarshal(cmd.Data, &request)
		if err != nil {
			f.logger.Error("cannot to unmarshal the request", zap.Error(err), zap.ByteString("request", cmd.Data))
			return err
		}
		var rules [][]string
		for _, rule := range request.Rules {
			rules = append(rules, rule.GetItems())
		}
		effected, err := f.enforcer.AddPolicySelf(f.shouldPersist, request.Sec, request.PType, rules)
		if err != nil {
			return err
		}
		return f.putPolicy(request.Sec, request.PType, effected)
	case command.Command_COMMAND_TYPE_REMOVE:
		var request command.RemovePolicyRequest
		err := proto.Unmarshal(cmd.Data, &request)
		if err != nil {
			f.logger.Error("cannot to unmarshal the request", zap.Error(err), zap.ByteString("request", cmd.Data))
			return err
		}
		var rules [][]string
		for _, rule := range request.Rules {
			rules = append(rules, rule.GetItems())
		}
		effected, err := f.enforcer.RemovePolicySelf(f.shouldPersist, request.Sec, request.PType, rules)
		if err != nil {
			return err
		}
		return f.deletePolicy(request.Sec, request.PType, effected)
	case command.Command_COMMAND_TYPE_REMOVE_FILTERED:
		var request command.RemoveFilteredPolicyRequest
		err := proto.Unmarshal(cmd.Data, &request)
		if err != nil {
			f.logger.Error("cannot to unmarshal the request", zap.Error(err), zap.ByteString("request", cmd.Data))
			return err
		}
		effected, err := f.enforcer.RemoveFilteredPolicySelf(f.shouldPersist, request.Sec, request.PType, int(request.FieldIndex), request.FieldValues...)
		if err != nil {
			return err
		}
		return f.deletePolicy(request.Sec, request.PType, effected)
	case command.Command_COMMAND_TYPE_UPDATE:
		var request command.UpdatePolicyRequest
		err := proto.Unmarshal(cmd.Data, &request)
		if err != nil {
			f.logger.Error("cannot to unmarshal the request", zap.Error(err), zap.ByteString("request", cmd.Data))
			return err
		}
		effected, err := f.enforcer.UpdatePolicySelf(f.shouldPersist, request.Sec, request.PType, request.OldRule, request.NewRule)
		if err != nil {
			return err
		}
		if effected == false {
			return nil
		}
		return f.updatePolicy(request.Sec, request.PType, request.OldRule, request.NewRule)
	case command.Command_COMMAND_TYPE_CLEAR:
		f.enforcer.ClearPolicy()
		return f.clearPolicy()
	default:
		err := fmt.Errorf("unknown command: %v", log)
		f.logger.Error(err.Error())
		return err
	}
}

// Restore is used to restore an FSM from a snapshot. It is not called
// concurrently with any other command. The FSM must discard all previous
// state.
func (f *FSM) Restore(rc io.ReadCloser) error {
	dbPath := f.db.Path()
	err := f.db.Close()
	if err != nil {
		f.logger.Error("failed to close database file", zap.Error(err))
		return err
	}

	gz, err := gzip.NewReader(rc)
	if err != nil {
		f.logger.Error("failed to new gzip", zap.Error(err))
		return err
	}

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, gz); err != nil {
		f.logger.Error("failed to copy data", zap.Error(err))
		return err
	}

	err = gz.Close()
	if err != nil {
		f.logger.Error("failed to close the gzip", zap.Error(err))
		return err
	}

	err = ioutil.WriteFile(dbPath, buf.Bytes(), 0600)
	if err != nil {
		f.logger.Error("failed to restore the database file", zap.Error(err))
		return err
	}

	err = f.openDBFile(dbPath)
	if err != nil {
		f.logger.Error("failed to open the database file", zap.Error(err))
		return err
	}

	f.enforcer.ClearPolicy()
	err = f.loadPolicy()
	if err != nil {
		f.logger.Error("failed to load policy", zap.Error(err))
		return err
	}

	return nil
}

// Snapshot is used to support log compaction. This call should
// return an FSMSnapshot which can be used to save a point-in-time
// snapshot of the FSM. Apply and Snapshot are not called in multiple
// threads, but Apply will be called concurrently with Persist. This means
// the FSM should be implemented in a fashion that allows for concurrent
// updates while a snapshot is happening.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	writer := new(bytes.Buffer)
	gz, err := gzip.NewWriterLevel(writer, gzip.BestCompression)

	err = f.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(gz)
		return err
	})
	if err != nil {
		f.logger.Error("failed to backup database file", zap.Error(err))
		return nil, err
	}

	err = gz.Close()
	if err != nil {
		f.logger.Error("failed to close the gzip", zap.Error(err))
		return nil, err
	}

	return &fsmSnapshot{data: writer.Bytes(), logger: f.logger}, nil
}

type Rule struct {
	Sec   string   `json:"sec"`
	PType string   `json:"p_type"`
	Rule  []string `json:"rule"`
}

func newRuleBytes(sec, pType string, rule []string) ([]byte, error) {
	r := Rule{
		Sec:   sec,
		PType: pType,
		Rule:  rule,
	}

	key, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (f *FSM) CreateBucket(name []byte) error {
	return f.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(name)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create %s bucket", name))
		}
		return nil
	})
}

func (f *FSM) DeleteBucket(name []byte) error {
	return f.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(name)
	})
}

func (f *FSM) loadPolicy() error {
	return f.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(policyBucketName)
		err := bkt.ForEach(func(k, v []byte) error {
			var rule Rule
			err := jsoniter.Unmarshal(k, &rule)
			if err != nil {
				return err
			}
			_, err = f.enforcer.AddPolicySelf(f.shouldPersist, rule.Sec, rule.PType, [][]string{rule.Rule})
			if err != nil {
				return err
			}
			return nil
		})
		return err
	})
}

func (f *FSM) putPolicy(sec, pType string, rules [][]string) error {
	err := f.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(policyBucketName)
		for _, item := range rules {
			key, err := newRuleBytes(sec, pType, item)
			if err != nil {
				return err
			}

			value, err := bkt.NextSequence()
			if err != nil {
				return err
			}

			err = bkt.Put(key, []byte(strconv.FormatUint(value, 10)))
			if err != nil {
				return err
			}
		}
		return nil
	})

	return err
}

func (f *FSM) deletePolicy(sec, pType string, rules [][]string) error {
	err := f.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(policyBucketName)
		for _, item := range rules {
			key, err := newRuleBytes(sec, pType, item)
			if err != nil {
				return err
			}

			err = bkt.Delete(key)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return err
}

func (f *FSM) updatePolicy(sec, pType string, oldRule, newRule []string) error {
	err := f.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(policyBucketName)

		newKey, err := newRuleBytes(sec, pType, newRule)
		if err != nil {
			return err
		}
		value, err := bkt.NextSequence()
		if err != nil {
			return err
		}

		err = bkt.Put(newKey, []byte(strconv.FormatUint(value, 10)))
		if err != nil {
			return err
		}

		oldKey, err := newRuleBytes(sec, pType, oldRule)
		if err != nil {
			return err
		}
		return bkt.Delete(oldKey)
	})

	return err
}

func (f *FSM) clearPolicy() error {
	return f.db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(policyBucketName)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucket(policyBucketName)
		if err != nil {
			return err
		}
		return nil
	})
}

type fsmSnapshot struct {
	data   []byte
	logger *zap.Logger
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		if _, err := sink.Write(f.data); err != nil {
			f.logger.Error("cannot to write to sink", zap.Error(err))
			return err
		}
		return sink.Close()
	}()

	if err != nil {
		f.logger.Error("cannot to persist the fsm snapshot", zap.Error(err))
		return sink.Cancel()
	}

	return nil
}

func (f *fsmSnapshot) Release() {
	// noop
}
