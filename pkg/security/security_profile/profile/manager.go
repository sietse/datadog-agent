// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package profile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.uber.org/atomic"

	proto "github.com/DataDog/agent-payload/v5/cws/dumpsv1"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	"github.com/DataDog/datadog-agent/pkg/security/rconfig"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	timeResolver "github.com/DataDog/datadog-agent/pkg/security/resolvers/time"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// EventFilteringResult is used to compute metrics for the event filtering feature
type EventFilteringResult uint8

const (
	// NoProfile is used to count the events for which we didn't have a profile
	NoProfile EventFilteringResult = iota
	// InProfile is used to count the events that matched a profile
	InProfile
	// NotInProfile is used to count the events that didn't match their profile
	NotInProfile
	// UnstableProfile is used to count the events that didn't make it into a profile because their matching profile was
	// unstable
	UnstableProfile
	// WorkloadWarmup is used to count the unmatched events with a profile skipped due to workload warm up time
	WorkloadWarmup
)

// DefaultProfileName used as default profile name
const DefaultProfileName = "default"

func (efr EventFilteringResult) toTag() string {
	switch efr {
	case NoProfile:
		return fmt.Sprintf("in_profile:no_profile")
	case InProfile:
		return fmt.Sprintf("in_profile:true")
	case NotInProfile:
		return fmt.Sprintf("in_profile:false")
	case UnstableProfile:
		return fmt.Sprintf("in_profile:unstable_profile")
	}
	return ""
}

var (
	allEventFilteringResults           = []EventFilteringResult{NoProfile, InProfile, NotInProfile, UnstableProfile}
	errUnstableProfileSizeLimitReached = errors.New("unstable profile: size limit reached")
	errUnstableProfileTimeLimitReached = errors.New("unstable profile: time limit reached")
)

// SecurityProfileManager is used to manage Security Profiles
type SecurityProfileManager struct {
	config         *config.Config
	statsdClient   statsd.ClientInterface
	cgroupResolver *cgroup.Resolver
	timeResolver   *timeResolver.Resolver
	providers      []Provider

	manager                    *manager.Manager
	securityProfileMap         *ebpf.Map
	securityProfileSyscallsMap *ebpf.Map

	profilesLock sync.Mutex
	profiles     map[cgroupModel.WorkloadSelector]*SecurityProfile

	pendingCacheLock sync.Mutex
	pendingCache     *simplelru.LRU[cgroupModel.WorkloadSelector, *SecurityProfile]
	cacheHit         *atomic.Uint64
	cacheMiss        *atomic.Uint64

	eventFiltering map[model.EventType]map[EventFilteringResult]*atomic.Uint64
}

// NewSecurityProfileManager returns a new instance of SecurityProfileManager
func NewSecurityProfileManager(config *config.Config, statsdClient statsd.ClientInterface, cgroupResolver *cgroup.Resolver, timeResolver *timeResolver.Resolver, manager *manager.Manager) (*SecurityProfileManager, error) {
	var providers []Provider

	// instantiate directory provider
	if len(config.RuntimeSecurity.SecurityProfileDir) != 0 {
		dirProvider, err := NewDirectoryProvider(config.RuntimeSecurity.SecurityProfileDir, config.RuntimeSecurity.SecurityProfileWatchDir)
		if err != nil {
			return nil, fmt.Errorf("couldn't instantiate a new security profile directory provider: %w", err)
		}
		providers = append(providers, dirProvider)
	}

	// instantiate remote-config provider
	if config.RuntimeSecurity.RemoteConfigurationEnabled && config.RuntimeSecurity.SecurityProfileRCEnabled {
		rcProvider, err := rconfig.NewRCProfileProvider()
		if err != nil {
			return nil, fmt.Errorf("couldn't instantiate a new security profile remote-config provider: %w", err)
		}
		providers = append(providers, rcProvider)
	}

	profileCache, err := simplelru.NewLRU[cgroupModel.WorkloadSelector, *SecurityProfile](config.RuntimeSecurity.SecurityProfileCacheSize, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't create security profile cache: %w", err)
	}

	securityProfileMap, ok, _ := manager.GetMap("security_profiles")
	if !ok {
		return nil, fmt.Errorf("security_profiles map not found")
	}

	securityProfileSyscallsMap, ok, _ := manager.GetMap("secprofs_syscalls")
	if !ok {
		return nil, fmt.Errorf("secprofs_syscalls map not found")
	}

	m := &SecurityProfileManager{
		config:                     config,
		statsdClient:               statsdClient,
		providers:                  providers,
		manager:                    manager,
		securityProfileMap:         securityProfileMap,
		securityProfileSyscallsMap: securityProfileSyscallsMap,
		cgroupResolver:             cgroupResolver,
		timeResolver:               timeResolver,
		profiles:                   make(map[cgroupModel.WorkloadSelector]*SecurityProfile),
		pendingCache:               profileCache,
		cacheHit:                   atomic.NewUint64(0),
		cacheMiss:                  atomic.NewUint64(0),
		eventFiltering:             make(map[model.EventType]map[EventFilteringResult]*atomic.Uint64),
	}
	for i := model.EventType(0); i < model.MaxKernelEventType; i++ {
		m.eventFiltering[i] = make(map[EventFilteringResult]*atomic.Uint64)
		for _, result := range allEventFilteringResults {
			m.eventFiltering[i][result] = atomic.NewUint64(0)
		}
	}

	// register the manager to the provider(s)
	for _, p := range m.providers {
		p.SetOnNewProfileCallback(m.OnNewProfileEvent)
	}
	return m, nil
}

// Start runs the manager of Security Profiles
func (m *SecurityProfileManager) Start(ctx context.Context) {
	// start all providers
	for _, p := range m.providers {
		if err := p.Start(ctx); err != nil {
			seclog.Errorf("couldn't start profile provider: %v", err)
		}
	}

	// register the manager to the CGroup resolver
	_ = m.cgroupResolver.RegisterListener(cgroup.WorkloadSelectorResolved, m.OnWorkloadSelectorResolvedEvent)
	_ = m.cgroupResolver.RegisterListener(cgroup.CGroupDeleted, m.OnCGroupDeletedEvent)

	seclog.Infof("security profile manager started")

	<-ctx.Done()
	m.stop()
}

// propagateWorkloadSelectorsToProviders (thread unsafe) propagates the list of workload selectors to the Security
// Profiles providers.
func (m *SecurityProfileManager) propagateWorkloadSelectorsToProviders() {
	var selectors []cgroupModel.WorkloadSelector
	for selector := range m.profiles {
		selectors = append(selectors, selector)
	}

	for _, p := range m.providers {
		p.UpdateWorkloadSelectors(selectors)
	}
}

// OnWorkloadSelectorResolvedEvent is used to handle the creation of a new cgroup with its resolved tags
func (m *SecurityProfileManager) OnWorkloadSelectorResolvedEvent(workload *cgroupModel.CacheEntry) {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()
	workload.Lock()
	defer workload.Unlock()

	if workload.Deleted.Load() {
		// this workload was deleted before we had time to apply its profile, ignore
		return
	}

	// check if the workload of this selector already exists
	profile, ok := m.profiles[workload.WorkloadSelector]
	if !ok {
		// check the cache
		m.pendingCacheLock.Lock()
		defer m.pendingCacheLock.Unlock()
		profile, ok = m.pendingCache.Get(workload.WorkloadSelector)
		if ok {
			// remove profile from cache
			_ = m.pendingCache.Remove(workload.WorkloadSelector)

			// since the profile was in cache, it was removed from kernel space, load it now
			// (locking isn't necessary here, but added as a safeguard)
			profile.Lock()
			err := m.loadProfile(profile)
			profile.Unlock()

			if err != nil {
				seclog.Errorf("couldn't load security profile %s in kernel space: %v", profile.selector, err)
				return
			}

			// insert the profile in the list of active profiles
			m.profiles[workload.WorkloadSelector] = profile
		} else {
			// create a new entry
			profile = NewSecurityProfile(workload.WorkloadSelector, m.config.RuntimeSecurity.AnomalyDetectionEventTypes)
			m.profiles[workload.WorkloadSelector] = profile

			// notify the providers that we're interested in a new workload selector
			m.propagateWorkloadSelectorsToProviders()
		}
	}

	// make sure the profile keeps a reference to the workload
	m.LinkProfile(profile, workload)
}

// LinkProfile applies a profile to the provided workload
func (m *SecurityProfileManager) LinkProfile(profile *SecurityProfile, workload *cgroupModel.CacheEntry) {
	profile.Lock()
	defer profile.Unlock()

	// check if this instance of this workload is already tracked
	for _, w := range profile.Instances {
		if w.ID == workload.ID {
			// nothing to do, leave
			return
		}
	}

	// update the list of tracked instances
	profile.Instances = append(profile.Instances, workload)

	// can we apply the profile or is it not ready yet ?
	if profile.loadedInKernel {
		m.linkProfile(profile, workload)
	}
}

// UnlinkProfile removes the link between a workload and a profile
func (m *SecurityProfileManager) UnlinkProfile(profile *SecurityProfile, workload *cgroupModel.CacheEntry) {
	profile.Lock()
	defer profile.Unlock()

	// remove the workload from the list of instances of the Security Profile
	for key, val := range profile.Instances {
		if workload.ID == val.ID {
			profile.Instances = append(profile.Instances[0:key], profile.Instances[key+1:]...)
			break
		}
	}

	// remove link between the profile and the workload
	m.unlinkProfile(profile, workload)
}

// GetProfile returns a profile by its selector
func (m *SecurityProfileManager) GetProfile(selector cgroupModel.WorkloadSelector) *SecurityProfile {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()

	// check if this workload had a Security Profile
	return m.profiles[selector]
}

// FillProfileContextFromContainerID populates a SecurityProfileContext for the given container ID
func (m *SecurityProfileManager) FillProfileContextFromContainerID(id string, ctx *model.SecurityProfileContext) {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()

	for _, profile := range m.profiles {
		profile.Lock()
		for _, instance := range profile.Instances {
			instance.Lock()
			if instance.ID == id {
				ctx.Name = profile.Metadata.Name
				ctx.Version = profile.Version
				ctx.Tags = profile.Tags
				ctx.Status = profile.Status
			}
			instance.Unlock()
		}
		profile.Unlock()
	}
}

// FillProfileContextFromProfile fills the given ctx with profile infos
func FillProfileContextFromProfile(ctx *model.SecurityProfileContext, profile *SecurityProfile) {
	profile.Lock()
	defer profile.Unlock()

	ctx.Name = profile.Metadata.Name
	if ctx.Name == "" {
		ctx.Name = DefaultProfileName
	}

	ctx.Version = profile.Version
	ctx.Tags = profile.Tags
	ctx.Status = profile.Status
	ctx.AnomalyDetectionEventTypes = profile.anomalyDetectionEvents
}

// OnCGroupDeletedEvent is used to handle a CGroupDeleted event
func (m *SecurityProfileManager) OnCGroupDeletedEvent(workload *cgroupModel.CacheEntry) {
	// lookup the profile
	profile := m.GetProfile(workload.WorkloadSelector)
	if profile == nil {
		// nothing to do, leave
		return
	}

	// removes the link between the profile and this workload
	m.UnlinkProfile(profile, workload)

	// check if the profile should be deleted
	m.ShouldDeleteProfile(profile)
}

// ShouldDeleteProfile checks if a profile should be deleted (happens if no instance is linked to it)
func (m *SecurityProfileManager) ShouldDeleteProfile(profile *SecurityProfile) {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()
	profile.Lock()
	defer profile.Unlock()

	// check if the profile should be deleted
	if len(profile.Instances) != 0 {
		// this profile is still in use, leave now
		return
	}

	// remove the profile from the list of profiles
	delete(m.profiles, profile.selector)

	// propagate the workload selectors
	m.propagateWorkloadSelectorsToProviders()

	if profile.loadedInKernel {
		// remove profile from kernel space
		m.unloadProfile(profile)
	}

	// cleanup profile before insertion in cache
	profile.reset()

	if profile.selector.IsEmpty() {
		// do not insert in cache
		return
	}

	// add profile in cache
	m.pendingCacheLock.Lock()
	defer m.pendingCacheLock.Unlock()
	m.pendingCache.Add(profile.selector, profile)
}

// OnNewProfileEvent handles the arrival of a new profile (or the new version of a profile) from a provider
func (m *SecurityProfileManager) OnNewProfileEvent(selector cgroupModel.WorkloadSelector, newProfile *proto.SecurityProfile) {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()

	// Update the Security Profile content
	profile, ok := m.profiles[selector]
	if !ok {
		// this was likely a short-lived workload, cache the profile in case this workload comes back
		profile = NewSecurityProfile(selector, m.config.RuntimeSecurity.AnomalyDetectionEventTypes)
	}

	if profile.Version == newProfile.Version {
		// this is the same file, ignore
		return
	}

	profile.Lock()
	defer profile.Unlock()
	profile.loadedInKernel = false

	// decode the content of the profile
	ProtoToSecurityProfile(profile, newProfile)

	// prepare the profile for insertion
	m.prepareProfile(profile)

	if !ok {
		// insert in cache and leave
		m.pendingCacheLock.Lock()
		defer m.pendingCacheLock.Unlock()
		m.pendingCache.Add(selector, profile)
		return
	}

	// load the profile in kernel space
	if err := m.loadProfile(profile); err != nil {
		seclog.Errorf("couldn't load security profile %s in kernel space: %v", profile.selector, err)
		return
	}

	// link all workloads
	for _, workload := range profile.Instances {
		m.linkProfile(profile, workload)
	}
}

func (m *SecurityProfileManager) stop() {
	// stop all providers
	for _, p := range m.providers {
		if err := p.Stop(); err != nil {
			seclog.Errorf("couldn't stop profile provider: %v", err)
		}
	}
}

// SendStats sends metrics about the Security Profile manager
func (m *SecurityProfileManager) SendStats() error {
	m.profilesLock.Lock()
	defer m.profilesLock.Unlock()
	if val := float64(len(m.profiles)); val > 0 {
		if err := m.statsdClient.Gauge(metrics.MetricSecurityProfileActiveProfiles, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSecurityProfileActiveProfiles: %w", err)
		}
	}

	for _, profile := range m.profiles {
		if profile.loadedInKernel { // make sure the profile is loaded
			if err := profile.SendStats(m.statsdClient); err != nil {
				return fmt.Errorf("couldn't send metrics for [%s]: %w", profile.selector.String(), err)
			}
		}
	}

	m.pendingCacheLock.Lock()
	defer m.pendingCacheLock.Unlock()
	if val := float64(m.pendingCache.Len()); val > 0 {
		if err := m.statsdClient.Gauge(metrics.MetricSecurityProfileCacheLen, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSecurityProfileCacheLen: %w", err)
		}
	}

	if val := int64(m.cacheHit.Swap(0)); val > 0 {
		if err := m.statsdClient.Count(metrics.MetricSecurityProfileCacheHit, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSecurityProfileCacheHit: %w", err)
		}
	}

	if val := int64(m.cacheMiss.Swap(0)); val > 0 {
		if err := m.statsdClient.Count(metrics.MetricSecurityProfileCacheMiss, val, []string{}, 1.0); err != nil {
			return fmt.Errorf("couldn't send MetricSecurityProfileCacheMiss: %w", err)
		}
	}

	for evtType, filteringCounts := range m.eventFiltering {
		for result, count := range filteringCounts {
			tags := []string{fmt.Sprintf("event_type:%s", evtType), result.toTag()}
			if value := count.Swap(0); value > 0 {
				if err := m.statsdClient.Count(metrics.MetricSecurityProfileEventFiltering, int64(value), tags, 1.0); err != nil {
					return fmt.Errorf("couldn't send MetricSecurityProfileEventFiltering metric: %w", err)
				}
			}
		}
	}

	return nil
}

// prepareProfile (thread unsafe) generates eBPF programs and cookies to prepare for kernel space insertion
func (m *SecurityProfileManager) prepareProfile(profile *SecurityProfile) {
	// generate cookies for the profile
	profile.generateCookies()

	// TODO: generate eBPF programs and make sure the profile is ready to be inserted in kernel space
}

// loadProfile (thread unsafe) loads a Security Profile in kernel space
func (m *SecurityProfileManager) loadProfile(profile *SecurityProfile) error {
	profile.loadedInKernel = true
	profile.loadedNano = uint64(m.timeResolver.ComputeMonotonicTimestamp(time.Now()))

	// push kernel space filters
	if err := m.securityProfileSyscallsMap.Put(profile.profileCookie, profile.generateSyscallsFilters()); err != nil {
		return fmt.Errorf("couldn't push syscalls filter: %w", err)
	}

	// TODO: load generated programs
	seclog.Debugf("security profile %s (version:%s status:%s) loaded in kernel space", profile.Metadata.Name, profile.Version, profile.Status.String())
	return nil
}

// unloadProfile (thread unsafe) unloads a Security Profile from kernel space
func (m *SecurityProfileManager) unloadProfile(profile *SecurityProfile) {
	profile.loadedInKernel = false

	// remove kernel space filters
	if err := m.securityProfileSyscallsMap.Delete(profile.profileCookie); err != nil {
		seclog.Errorf("coudln't remove syscalls filter: %v", err)
	}

	// TODO: delete all kernel space programs
	seclog.Debugf("security profile %s (version:%s status:%s) unloaded from kernel space", profile.Metadata.Name, profile.Version, profile.Status.String())
}

// linkProfile (thread unsafe) updates the kernel space mapping between a workload and its profile
func (m *SecurityProfileManager) linkProfile(profile *SecurityProfile, workload *cgroupModel.CacheEntry) {
	if err := m.securityProfileMap.Put([]byte(workload.ID), profile.generateKernelSecurityProfileDefinition()); err != nil {
		seclog.Errorf("couldn't link workload %s (selector: %s) with profile %s: %v", workload.ID, workload.WorkloadSelector.String(), profile.Metadata.Name, err)
		return
	}
	seclog.Infof("workload %s (selector: %s) successfully linked to profile %s", workload.ID, workload.WorkloadSelector.String(), profile.Metadata.Name)
}

// unlinkProfile (thread unsafe) updates the kernel space mapping between a workload and its profile
func (m *SecurityProfileManager) unlinkProfile(profile *SecurityProfile, workload *cgroupModel.CacheEntry) {
	if !profile.loadedInKernel {
		return
	}

	if err := m.securityProfileMap.Delete([]byte(workload.ID)); err != nil {
		seclog.Errorf("couldn't unlink workload %s with profile %s: %v", workload.WorkloadSelector.String(), profile.Metadata.Name, err)
	}
	seclog.Infof("workload %s (selector: %s) successfully unlinked from profile %s", workload.ID, workload.WorkloadSelector.String(), profile.Metadata.Name)
}

func (m *SecurityProfileManager) LookupEventInProfiles(event *model.Event) {
	// ignore events with an error
	if event.Error != nil {
		return
	}

	// shortcut for dedicated anomaly detection events
	if IsAnomalyDetectionEvent(event.GetEventType()) {
		event.AddToFlags(model.EventFlagsSecurityProfileInProfile)
		return
	}

	// create profile selector
	event.FieldHandlers.ResolveContainerTags(event, event.ContainerContext)
	if len(event.ContainerContext.Tags) == 0 {
		return
	}

	selector, err := cgroupModel.NewWorkloadSelector(utils.GetTagValue("image_name", event.ContainerContext.Tags), utils.GetTagValue("image_tag", event.ContainerContext.Tags))
	if err != nil {
		return
	}

	// lookup profile
	profile := m.GetProfile(selector)
	if profile == nil || profile.Status == 0 {
		m.eventFiltering[event.GetEventType()][NoProfile].Inc()
		return
	}

	_ = event.FieldHandlers.ResolveContainerCreatedAt(event, event.ContainerContext)

	markEventAsInProfile := func(inProfile bool) {
		// link the profile to the event only if it's a valid event for profile without any error
		FillProfileContextFromProfile(&event.SecurityProfileContext, profile)

		if inProfile {
			event.AddToFlags(model.EventFlagsSecurityProfileInProfile)
			m.eventFiltering[event.GetEventType()][InProfile].Inc()
		} else {
			m.eventFiltering[event.GetEventType()][NotInProfile].Inc()
		}
	}

	// check if the event should be injected in the profile automatically
	if autoLearned, err := m.tryAutolearn(profile, event); err != nil {
		return
	} else if autoLearned {
		markEventAsInProfile(true)
		return
	}

	// check if the event is in its profile
	found, err := profile.ActivityTree.Contains(event, activity_tree.ProfileDrift)
	if err != nil {
		// ignore, evaluation failed
		m.eventFiltering[event.GetEventType()][NoProfile].Inc()
		return
	}

	markEventAsInProfile(found)
}

// tryAutolearn tries to autolearn the input event. The first return values is true if the event was autolearned,
// in which case the second return value tells whether the node was already in the profile.
func (m *SecurityProfileManager) tryAutolearn(profile *SecurityProfile, event *model.Event) (bool, error) {
	// check if the unstable size limit was reached
	if profile.ActivityTree.Stats.ApproximateSize() >= m.config.RuntimeSecurity.AnomalyDetectionUnstableProfileSizeThreshold {
		m.eventFiltering[event.GetEventType()][UnstableProfile].Inc()
		return false, errUnstableProfileSizeLimitReached
	}

	var nodeType activity_tree.NodeGenerationType

	// check if we are at the beginning of a workload lifetime
	if event.ResolveEventTime().Sub(time.Unix(0, int64(event.ContainerContext.CreatedAt))) < m.config.RuntimeSecurity.AnomalyDetectionWorkloadWarmupPeriod {
		nodeType = activity_tree.WorkloadWarmup
	} else {
		// have we reached the stable state time limit ?
		lastAnomalyNano, ok := profile.lastAnomalyNano[event.GetEventType()]
		if !ok {
			profile.lastAnomalyNano[event.GetEventType()] = profile.loadedNano
			lastAnomalyNano = profile.loadedNano
		}
		if time.Duration(event.TimestampRaw-lastAnomalyNano) >= m.config.RuntimeSecurity.AnomalyDetectionMinimumStablePeriod {
			return false, nil
		}

		// have we reached the unstable time limit ?
		if time.Duration(event.TimestampRaw-profile.loadedNano) >= m.config.RuntimeSecurity.AnomalyDetectionUnstableProfileTimeThreshold {
			m.eventFiltering[event.GetEventType()][UnstableProfile].Inc()
			return false, errUnstableProfileTimeLimitReached
		}

		nodeType = activity_tree.ProfileDrift
	}

	// try to insert the event in the profile
	newEntry, err := profile.ActivityTree.Insert(event, nodeType)
	if err != nil {
		m.eventFiltering[event.GetEventType()][NoProfile].Inc()
		return false, err
	}

	// the event was either already in the profile, or has just been inserted
	event.AddToFlags(model.EventFlagsSecurityProfileInProfile)

	if newEntry {
		profile.lastAnomalyNano[event.GetEventType()] = event.TimestampRaw
	}

	return true, nil
}
