//go:build !android_slim

package stats

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"go.etcd.io/bbolt"
)

func finishTxn(tx *bbolt.Tx, commit bool) (err error) {
	if commit {
		err = errors.Annotate(tx.Commit(), "committing: %w")
	} else {
		err = errors.Annotate(tx.Rollback(), "rolling back: %w")
	}

	return err
}

// bucketNameLen is the length of a bucket, a 64-bit unsigned integer.
const bucketNameLen = 8

// idToUnitName converts a numerical ID into a database unit name.
func idToUnitName(id uint32) (name []byte) {
	n := [bucketNameLen]byte{}
	binary.BigEndian.PutUint64(n[:], uint64(id))

	return n[:]
}

// unitNameToID converts a database unit name into a numerical ID.  ok is false
// if name is not a valid database unit name.
func unitNameToID(name []byte) (id uint32, ok bool) {
	if len(name) < bucketNameLen {
		return 0, false
	}

	return uint32(binary.BigEndian.Uint64(name)), true
}

// loadUnitFromDB loads unit by id from the database.
func (s *StatsCtx) loadUnitFromDB(tx *bbolt.Tx, id uint32) (udb *unitDB) {
	bkt := tx.Bucket(idToUnitName(id))
	if bkt == nil {
		return nil
	}

	s.logger.Debug("loading unit", "id", id)

	var buf bytes.Buffer
	buf.Write(bkt.Get([]byte{0}))
	udb = &unitDB{}

	err := gob.NewDecoder(&buf).Decode(udb)
	if err != nil {
		s.logger.Error("gob decode", slogutil.KeyError, err)

		return nil
	}

	return udb
}

// flushUnitToDB puts udb to the database at id.
func (s *StatsCtx) flushUnitToDB(udb *unitDB, tx *bbolt.Tx, id uint32) (err error) {
	s.logger.Debug("flushing unit", "id", id, "req_num", udb.NTotal)

	bkt, err := tx.CreateBucketIfNotExists(idToUnitName(id))
	if err != nil {
		return fmt.Errorf("creating bucket: %w", err)
	}

	buf := &bytes.Buffer{}
	err = gob.NewEncoder(buf).Encode(udb)
	if err != nil {
		return fmt.Errorf("encoding unit: %w", err)
	}

	err = bkt.Put([]byte{0}, buf.Bytes())
	if err != nil {
		return fmt.Errorf("putting unit to database: %w", err)
	}

	return nil
}
