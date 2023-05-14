// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package usm

import (
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/DataDog/gopsutil/process"
	"github.com/cilium/ebpf"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/common"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var openSSLProbes = []manager.ProbesSelector{
	&manager.BestEffort{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_read_ex",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_read_ex",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_write_ex",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_write_ex",
				},
			},
		},
	},
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_do_handshake",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_do_handshake",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_connect",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_connect",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_set_bio",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_set_fd",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_read",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_read",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_write",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__SSL_write",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__SSL_shutdown",
				},
			},
		},
	},
}

var cryptoProbes = []manager.ProbesSelector{
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__BIO_new_socket",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__BIO_new_socket",
				},
			},
		},
	},
}

var gnuTLSProbes = []manager.ProbesSelector{
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_handshake",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__gnutls_handshake",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_transport_set_int2",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_transport_set_ptr",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_transport_set_ptr2",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_record_recv",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__gnutls_record_recv",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_record_send",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uretprobe__gnutls_record_send",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_bye",
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: "uprobe__gnutls_deinit",
				},
			},
		},
	},
}

const (
	sslSockByCtxMap        = "ssl_sock_by_ctx"
	sharedLibrariesPerfMap = "shared_libraries"
	doSysOpen              = "do_sys_open"
	doSysOpenAt2           = "do_sys_openat2"
)

// probe used for streaming shared library events
var (
	kprobeKretprobePrefix = []string{"kprobe", "kretprobe"}
)

type sslProgram struct {
	cfg                     *config.Config
	sockFDMap               *ebpf.Map
	perfHandler             *ddebpf.PerfHandler
	manager                 *errtelemetry.Manager
	sysOpenHooksIdentifiers []manager.ProbeIdentificationPair
	eventLoopWaitGroup      sync.WaitGroup
	eventLoopDoneChannel    chan struct{}
	procRoot                string
	soRules                 []soRule
	processMonitor          *monitor.ProcessMonitor
	soRegistry              *soRegistry
}

var _ subprogram = &sslProgram{}

func newSSLProgram(c *config.Config, sockFDMap *ebpf.Map) *sslProgram {
	if !c.EnableHTTPSMonitoring || !http.HTTPSSupported(c) {
		return nil
	}

	return &sslProgram{
		cfg:                     c,
		sockFDMap:               sockFDMap,
		perfHandler:             ddebpf.NewPerfHandler(100),
		sysOpenHooksIdentifiers: getSysOpenHooksIdentifiers(),
		eventLoopWaitGroup:      sync.WaitGroup{},
		eventLoopDoneChannel:    make(chan struct{}),
		procRoot:                util.GetProcRoot(),
		processMonitor:          monitor.GetProcessMonitor(),
		soRegistry: &soRegistry{
			byID:          make(map[pathIdentifier]*soRegistration),
			byPID:         make(map[uint32]pathIdentifierSet),
			blocklistByID: make(pathIdentifierSet),
		},
	}
}

func (o *sslProgram) ConfigureManager(m *errtelemetry.Manager) {
	o.manager = m

	m.PerfMaps = append(m.PerfMaps, &manager.PerfMap{
		Map: manager.Map{Name: sharedLibrariesPerfMap},
		PerfMapOptions: manager.PerfMapOptions{
			PerfRingBufferSize: 8 * os.Getpagesize(),
			Watermark:          1,
			RecordHandler:      o.perfHandler.RecordHandler,
			LostHandler:        o.perfHandler.LostHandler,
			RecordGetter:       o.perfHandler.RecordGetter,
		},
	})

	for _, identifier := range o.sysOpenHooksIdentifiers {
		m.Probes = append(m.Probes,
			&manager.Probe{
				ProbeIdentificationPair: identifier,
				KProbeMaxActive:         maxActive,
			},
		)
	}
}

func (o *sslProgram) ConfigureOptions(options *manager.Options) {
	options.MapSpecEditors[sslSockByCtxMap] = manager.MapSpecEditor{
		Type:       ebpf.Hash,
		MaxEntries: uint32(o.cfg.MaxTrackedConnections),
		EditorFlag: manager.EditMaxEntries,
	}

	for _, identifier := range o.sysOpenHooksIdentifiers {
		options.ActivatedProbes = append(options.ActivatedProbes,
			&manager.ProbeSelector{
				ProbeIdentificationPair: identifier,
			},
		)
	}

	if options.MapEditors == nil {
		options.MapEditors = make(map[string]*ebpf.Map)
	}

	options.MapEditors[probes.SockByPidFDMap] = o.sockFDMap
}

func (o *sslProgram) Start() {
	// Setup shared library watcher and configure the appropriate callbacks
	rules := []soRule{
		{
			re:           regexp.MustCompile(`libssl.so`),
			registerCB:   addHooks(o.manager, openSSLProbes),
			unregisterCB: removeHooks(o.manager, openSSLProbes),
		},
		{
			re:           regexp.MustCompile(`libcrypto.so`),
			registerCB:   addHooks(o.manager, cryptoProbes),
			unregisterCB: removeHooks(o.manager, cryptoProbes),
		},
		{
			re:           regexp.MustCompile(`libgnutls.so`),
			registerCB:   addHooks(o.manager, gnuTLSProbes),
			unregisterCB: removeHooks(o.manager, gnuTLSProbes),
		},
	}

	thisPID, err := util.GetRootNSPID()
	if err != nil {
		log.Warnf("soWatcher Start can't get root namespace pid %s", err)
	}

	_ = util.WithAllProcs(o.procRoot, func(pid int) error {
		if pid == thisPID { // don't scan ourself
			return nil
		}

		// report silently parsing /proc error as this could happen
		// just exit processes
		proc, err := process.NewProcess(int32(pid))
		if err != nil {
			log.Debugf("process %d parsing failed %s", pid, err)
			return nil
		}
		mmaps, err := proc.MemoryMaps(true)
		if err != nil {
			log.Tracef("process %d maps parsing failed %s", pid, err)
			return nil
		}

		root := fmt.Sprintf("%s/%d/root", o.procRoot, pid)
		for _, m := range *mmaps {
			for _, r := range rules {
				if r.re.MatchString(m.Path) {
					o.soRegistry.register(root, m.Path, uint32(pid), r)
					break
				}
			}
		}

		return nil
	})

	if err := o.processMonitor.Initialize(); err != nil {
		log.Errorf("can't initialize process monitor %s", err)
		return
	}
	cleanupExit, err := o.processMonitor.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXIT,
		Metadata: monitor.ANY,
		Callback: o.soRegistry.unregister,
	})
	if err != nil {
		log.Errorf("can't subscribe to process monitor exit event %s", err)
		return
	}

	o.eventLoopWaitGroup.Add(1)
	go func() {
		defer func() {
			// Removing the registration of our hook.
			cleanupExit()
			// Stopping the process monitor (if we're the last instance)
			o.processMonitor.Stop()
			// cleaning up all active hooks.
			o.soRegistry.cleanup()
			// marking we're finished.
			o.eventLoopWaitGroup.Done()
		}()

		for {
			select {
			case <-o.eventLoopDoneChannel:
				return
			case event, ok := <-o.perfHandler.DataChannel:
				if !ok {
					return
				}

				lib := toLibPath(event.Data)
				if int(lib.Pid) == thisPID {
					// don't scan ourself
					event.Done()
					continue
				}

				path := toBytes(&lib)
				libPath := string(path)
				procPid := fmt.Sprintf("%s/%d", o.procRoot, lib.Pid)
				root := procPid + "/root"
				// use cwd of the process as root if the path is relative
				if libPath[0] != '/' {
					root = procPid + "/cwd"
					libPath = "/" + libPath
				}

				for _, r := range rules {
					if r.re.Match(path) {
						o.soRegistry.register(root, libPath, lib.Pid, r)
						break
					}
				}
				event.Done()
			case <-o.perfHandler.LostChannel:
				// Nothing to do in this case
				break
			}
		}
	}()
}

func (o *sslProgram) Stop() {
	// Detaching the hooks.
	for _, identifier := range o.sysOpenHooksIdentifiers {
		probe, found := o.manager.GetProbe(identifier)
		if !found {
			continue
		}
		if err := probe.Stop(); err != nil {
			log.Errorf("Failed to stop hook %q. Error: %s", identifier.EBPFFuncName, err)
		}
	}
	// We must stop the watcher first, as we can read from the perfHandler, before terminating the perfHandler, otherwise
	// we might try to send events over the perfHandler.
	close(o.eventLoopDoneChannel)
	o.eventLoopWaitGroup.Wait()
	o.perfHandler.Stop()
}

func addHooks(m *errtelemetry.Manager, probes []manager.ProbesSelector) func(pathIdentifier, string, string) error {
	return func(id pathIdentifier, root string, path string) error {
		uid := getUID(id)

		elfFile, err := elf.Open(root + path)
		if err != nil {
			return err
		}
		defer elfFile.Close()

		symbolsSet := make(common.StringSet, 0)
		symbolsSetBestEffort := make(common.StringSet, 0)
		for _, singleProbe := range probes {
			_, isBestEffort := singleProbe.(*manager.BestEffort)
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				_, symbol, ok := strings.Cut(selector.EBPFFuncName, "__")
				if !ok {
					continue
				}
				if isBestEffort {
					symbolsSetBestEffort[symbol] = struct{}{}
				} else {
					symbolsSet[symbol] = struct{}{}
				}
			}
		}
		symbolMap, err := bininspect.GetAllSymbolsByName(elfFile, symbolsSet)
		if err != nil {
			return err
		}
		/* Best effort to resolve symbols, so we don't care about the error */
		symbolMapBestEffort, _ := bininspect.GetAllSymbolsByName(elfFile, symbolsSetBestEffort)

		for _, singleProbe := range probes {
			_, isBestEffort := singleProbe.(*manager.BestEffort)
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				identifier := manager.ProbeIdentificationPair{
					EBPFFuncName: selector.EBPFFuncName,
					UID:          uid,
				}
				singleProbe.EditProbeIdentificationPair(selector, identifier)
				probe, found := m.GetProbe(identifier)
				if found {
					if !probe.IsRunning() {
						err := probe.Attach()
						if err != nil {
							return err
						}
					}

					continue
				}

				_, symbol, ok := strings.Cut(selector.EBPFFuncName, "__")
				if !ok {
					continue
				}

				sym := symbolMap[symbol]
				if isBestEffort {
					sym, found = symbolMapBestEffort[symbol]
					if !found {
						continue
					}
				}
				manager.SanitizeUprobeAddresses(elfFile, []elf.Symbol{sym})
				offset, err := bininspect.SymbolToOffset(elfFile, sym)
				if err != nil {
					return err
				}

				newProbe := &manager.Probe{
					ProbeIdentificationPair: identifier,
					BinaryPath:              root + path,
					UprobeOffset:            uint64(offset),
					HookFuncName:            symbol,
				}
				_ = m.AddHook("", newProbe)
			}
			if err := singleProbe.RunValidator(m.Manager); err != nil {
				return err
			}
		}

		return nil
	}
}

func removeHooks(m *errtelemetry.Manager, probes []manager.ProbesSelector) func(pathIdentifier) error {
	return func(lib pathIdentifier) error {
		uid := getUID(lib)
		for _, singleProbe := range probes {
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				identifier := manager.ProbeIdentificationPair{
					EBPFFuncName: selector.EBPFFuncName,
					UID:          uid,
				}
				probe, found := m.GetProbe(identifier)
				if !found {
					continue
				}

				program := probe.Program()
				err := m.DetachHook(identifier)
				if err != nil {
					log.Debugf("detach hook %s/%s : %s", selector.EBPFFuncName, uid, err)
				}
				if program != nil {
					program.Close()
				}
			}
		}

		return nil
	}
}

// getUID() return a key of length 5 as the kernel uprobe registration path is limited to a length of 64
// ebpf-manager/utils.go:GenerateEventName() MaxEventNameLen = 64
// MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
//
// Length 5 is arbitrary value as the full string of the eventName format is
//
//	fmt.Sprintf("%s_%.*s_%s_%s", probeType, maxFuncNameLen, functionName, UID, attachPIDstr)
//
// functionName is variable but with a minimum guarantee of 10 chars
func getUID(lib pathIdentifier) string {
	return lib.Key()[:5]
}

func (*sslProgram) GetAllUndefinedProbes() []manager.ProbeIdentificationPair {
	var probeList []manager.ProbeIdentificationPair

	for _, sslProbeList := range [][]manager.ProbesSelector{openSSLProbes, cryptoProbes, gnuTLSProbes} {
		for _, singleProbe := range sslProbeList {
			for _, identifier := range singleProbe.GetProbesIdentificationPairList() {
				probeList = append(probeList, manager.ProbeIdentificationPair{
					EBPFFuncName: identifier.EBPFFuncName,
				})
			}
		}
	}

	for _, hook := range []string{doSysOpen, doSysOpenAt2} {
		for _, kprobe := range kprobeKretprobePrefix {
			probeList = append(probeList, manager.ProbeIdentificationPair{
				EBPFFuncName: kprobe + "__" + hook,
			})
		}
	}

	return probeList
}

func sysOpenAt2Supported() bool {
	missing, err := ddebpf.VerifyKernelFuncs(doSysOpenAt2)
	if err == nil && len(missing) == 0 {
		return true
	}
	kversion, err := kernel.HostVersion()
	if err != nil {
		log.Error("could not determine the current kernel version. fallback to do_sys_open")
		return false
	}

	return kversion >= kernel.VersionCode(5, 6, 0)
}

// getSysOpenHooksIdentifiers returns the kprobe and kretprobe for the chosen kernel function to hook, to get notification
// about file opening. Before kernel 5.6 we use do_sys_open, otherwise we use do_sys_openat2.
func getSysOpenHooksIdentifiers() []manager.ProbeIdentificationPair {
	probeSysOpen := doSysOpen
	if sysOpenAt2Supported() {
		probeSysOpen = doSysOpenAt2
	}

	res := make([]manager.ProbeIdentificationPair, len(kprobeKretprobePrefix))
	for i, kprobe := range kprobeKretprobePrefix {
		res[i] = manager.ProbeIdentificationPair{
			EBPFFuncName: kprobe + "__" + probeSysOpen,
			UID:          probeUID,
		}
	}

	return res
}
