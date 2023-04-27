// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/atomic"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// ResolverOpts defines hash resolver options
type ResolverOpts struct {
	// Enabled defines if the hash resolver should be enabled
	Enabled bool
	// MaxFileSize defines the maximum size of the files that the hash resolver is allowed to hash
	MaxFileSize int64
	// HashAlgorithms defines the hashes that hash resolver needs to compute
	HashAlgorithms []model.HashAlgorithm
	// EventTypes defines the list of event types for which we may compute hashes. Warning: enabling a FIM event will
	// automatically make the hash resolver also hash process binary files.
	EventTypes []model.EventType
}

// Resolver represents a cache for mountpoints and the corresponding file systems
type Resolver struct {
	opts         ResolverOpts
	statsdClient statsd.ClientInterface
	limiter      *rate.Limiter

	// stats
	hashCount map[model.EventType]map[model.HashAlgorithm]*atomic.Uint64
	hashMiss  map[model.EventType]map[model.HashSate]*atomic.Uint64
}

// NewResolver returns a new instance of the hash resolver
func NewResolver(c *config.RuntimeSecurityConfig, statsdClient statsd.ClientInterface) *Resolver {
	if !c.HashResolverEnabled {
		return &Resolver{
			opts: ResolverOpts{
				Enabled: false,
			},
		}
	}

	r := &Resolver{
		opts: ResolverOpts{
			Enabled:        true,
			MaxFileSize:    c.HashResolverMaxFileSize,
			HashAlgorithms: c.HashResolverHashAlgorithms,
			EventTypes:     c.HashResolverEventTypes,
		},
		statsdClient: statsdClient,
		limiter:      rate.NewLimiter(rate.Limit(c.HashResolverMaxHashRate), c.HashResolverMaxHashBurst),
		hashCount:    make(map[model.EventType]map[model.HashAlgorithm]*atomic.Uint64),
		hashMiss:     make(map[model.EventType]map[model.HashSate]*atomic.Uint64),
	}

	// generate counters
	for i := model.EventType(0); i < model.MaxKernelEventType; i++ {
		r.hashCount[i] = make(map[model.HashAlgorithm]*atomic.Uint64, model.MaxHashAlgorithm)
		for j := model.HashAlgorithm(0); j < model.MaxHashAlgorithm; j++ {
			r.hashCount[i][j] = atomic.NewUint64(0)
		}

		r.hashMiss[i] = make(map[model.HashSate]*atomic.Uint64, model.MaxHashState)
		for j := model.HashSate(0); j < model.MaxHashState; j++ {
			r.hashMiss[i][j] = atomic.NewUint64(0)
		}
	}
	return r
}

// ComputeHashes computes the hashes of the provided file event
func (resolver *Resolver) ComputeHashes(event *model.Event, file *model.FileEvent) []string {
	if !resolver.opts.Enabled {
		return nil
	}

	// check state
	if file.HashState == model.Done {
		return file.Hashes
	}
	if file.HashState != model.NoHash {
		// this file was already processed and an error occurred, nothing else to do
		return nil
	}

	// check if the resolver is allowed to hash this event type
	if !slices.Contains[model.EventType](resolver.opts.EventTypes, event.GetEventType()) {
		file.HashState = model.EventTypeNotConfigured
		resolver.hashMiss[event.GetEventType()][model.EventTypeNotConfigured].Inc()
		return nil
	}

	if err := resolver.hash(event, file); err != nil {
		resolver.hashMiss[event.GetEventType()][model.UnknownHashError].Inc()
		seclog.Errorf("hash computation failed: %v", err)
		return nil
	}

	return file.Hashes
}

// getHashFunction returns the hash function for the provided algorithm
func (resolver *Resolver) getHashFunction(algorithm model.HashAlgorithm) hash.Hash {
	switch algorithm {
	case model.SHA1:
		return sha1.New()
	case model.SHA256:
		return sha256.New()
	case model.MD5:
		return md5.New()
	default:
		return nil
	}
}

// hash hashes the provided file event
func (resolver *Resolver) hash(event *model.Event, file *model.FileEvent) error {
	// open the target file
	f, err := os.Open(filepath.Join(utils.ProcRootPath(int32(event.ProcessContext.Pid)), event.FieldHandlers.ResolveFilePath(event, file)))
	if err != nil {
		if os.IsNotExist(err) {
			file.HashState = model.FileNotFound
			resolver.hashMiss[event.GetEventType()][model.FileNotFound].Inc()
			return nil
		}
		return fmt.Errorf("couldn't open file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("couldn't stat file: %w", err)
	}

	// is this a regular file ?
	if !fi.Mode().IsRegular() {
		return nil
	}

	// check file size
	if fi.Size() > resolver.opts.MaxFileSize {
		resolver.hashMiss[event.GetEventType()][model.FileTooBig].Inc()
		return nil
	}

	// check the rate limiter
	if !resolver.limiter.Allow() {
		// better luck next time
		resolver.hashMiss[event.GetEventType()][model.HashWasRateLimited].Inc()
		return nil
	}

	var hashers []io.Writer
	for _, algorithm := range resolver.opts.HashAlgorithms {
		h := resolver.getHashFunction(algorithm)
		if h == nil {
			// shouldn't happen, ignore
			continue
		}
		hashers = append(hashers, h)
	}
	multiWriter := io.MultiWriter(hashers...)

	if _, err = io.Copy(multiWriter, f); err != nil {
		return fmt.Errorf("couldn't compute %v hash(es): %w", resolver.opts.HashAlgorithms, err)
	}

	for i, algorithm := range resolver.opts.HashAlgorithms {
		var hashStr string
		if len(algorithm.String()) > 0 {
			hashStr += algorithm.String() + ":"
		}
		hashStr += hex.EncodeToString(hashers[i].(hash.Hash).Sum(nil))

		file.Hashes = append(file.Hashes, hashStr)
		resolver.hashCount[event.GetEventType()][algorithm].Inc()
	}

	file.HashState = model.Done
	return nil
}

// SendStats sends the resolver metrics
func (resolver *Resolver) SendStats() error {
	if !resolver.opts.Enabled {
		return nil
	}

	for evtType, hashCounts := range resolver.hashCount {
		for algorithm, count := range hashCounts {
			tags := []string{fmt.Sprintf("event_type:%s", evtType), fmt.Sprintf("hash:%s", algorithm)}
			if value := count.Swap(0); value > 0 {
				if err := resolver.statsdClient.Count(metrics.MetricHashResolverHashCount, int64(value), tags, 1.0); err != nil {
					return fmt.Errorf("couldn't send MetricHashResolverHashCount metric: %w", err)
				}
			}
		}
	}

	for evtType, hashMisses := range resolver.hashMiss {
		for reason, count := range hashMisses {
			tags := []string{fmt.Sprintf("event_type:%s", evtType), fmt.Sprintf("reason:%s", reason)}
			if value := count.Swap(0); value > 0 {
				if err := resolver.statsdClient.Count(metrics.MetricHashResolverHashMiss, int64(value), tags, 1.0); err != nil {
					return fmt.Errorf("couldn't send MetricHashResolverHashMiss metric: %w", err)
				}
			}
		}
	}
	return nil
}
