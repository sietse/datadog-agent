// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// !!!
// This is a generated file: regenerate with go run ./pkg/compliance/tools/k8s_types_generator.go
// !!!
package k8sconfig

import (
	"strconv"
	"strings"
	"time"
)

type K8sKubeApiserverConfig struct {
	AnonymousAuth                   bool                                 `json:"anonymousAuth"`                   // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuditLogMaxage                  int                                  `json:"auditLogMaxage"`                  // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuditLogMaxbackup               int                                  `json:"auditLogMaxbackup"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuditLogMaxsize                 int                                  `json:"auditLogMaxsize"`                 // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuditLogPath                    string                               `json:"auditLogPath"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuditPolicyFile                 *K8sConfigFileMeta                   `json:"auditPolicyFile"`                 // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuthorizationMode               []string                             `json:"authorizationMode"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	BindAddress                     string                               `json:"bindAddress"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ClientCaFile                    *K8sCertFileMeta                     `json:"clientCaFile"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	DisableAdmissionPlugins         []string                             `json:"disableAdmissionPlugins"`         // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	EnableAdmissionPlugins          []string                             `json:"enableAdmissionPlugins"`          // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	EncryptionProviderConfig        *K8sEncryptionProviderConfigFileMeta `json:"encryptionProviderConfig"`        // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	EtcdCafile                      *K8sCertFileMeta                     `json:"etcdCafile"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	EtcdCertfile                    *K8sCertFileMeta                     `json:"etcdCertfile"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	EtcdKeyfile                     *K8sKeyFileMeta                      `json:"etcdKeyfile"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	KubeletCertificateAuthority     *K8sCertFileMeta                     `json:"kubeletCertificateAuthority"`     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	KubeletClientCertificate        *K8sCertFileMeta                     `json:"kubeletClientCertificate"`        // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	KubeletClientKey                *K8sKeyFileMeta                      `json:"kubeletClientKey"`                // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Profiling                       bool                                 `json:"profiling"`                       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ProxyClientCertFile             *K8sCertFileMeta                     `json:"proxyClientCertFile"`             // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ProxyClientKeyFile              *K8sKeyFileMeta                      `json:"proxyClientKeyFile"`              // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestTimeout                  time.Duration                        `json:"requestTimeout"`                  // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderAllowedNames       []string                             `json:"requestheaderAllowedNames"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderClientCaFile       *K8sCertFileMeta                     `json:"requestheaderClientCaFile"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderExtraHeadersPrefix []string                             `json:"requestheaderExtraHeadersPrefix"` // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderGroupHeaders       []string                             `json:"requestheaderGroupHeaders"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderUsernameHeaders    []string                             `json:"requestheaderUsernameHeaders"`    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	SecurePort                      int                                  `json:"securePort"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ServiceAccountKeyFile           *K8sKeyFileMeta                      `json:"serviceAccountKeyFile"`           // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ServiceAccountLookup            bool                                 `json:"serviceAccountLookup"`            // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCertFile                     *K8sCertFileMeta                     `json:"tlsCertFile"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCipherSuites                 []string                             `json:"tlsCipherSuites"`                 // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsPrivateKeyFile               *K8sKeyFileMeta                      `json:"tlsPrivateKeyFile"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TokenAuthFile                   *K8sTokenFileMeta                    `json:"tokenAuthFile"`                   // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
}

func newK8sKubeApiserverConfig(flags map[string]string) *K8sKubeApiserverConfig {
	var res K8sKubeApiserverConfig
	if v, ok := flags["--anonymous-auth"]; ok {
		res.AnonymousAuth, _ = strconv.ParseBool(v)
	} else {
		res.AnonymousAuth, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--audit-log-maxage"]; ok {
		res.AuditLogMaxage, _ = strconv.Atoi(v)
	} else {
		res.AuditLogMaxage, _ = strconv.Atoi("0")
	}
	if v, ok := flags["--audit-log-maxbackup"]; ok {
		res.AuditLogMaxbackup, _ = strconv.Atoi(v)
	} else {
		res.AuditLogMaxbackup, _ = strconv.Atoi("0")
	}
	if v, ok := flags["--audit-log-maxsize"]; ok {
		res.AuditLogMaxsize, _ = strconv.Atoi(v)
	} else {
		res.AuditLogMaxsize, _ = strconv.Atoi("0")
	}
	if v, ok := flags["--audit-log-path"]; ok {
		res.AuditLogPath = v
	}
	if v, ok := flags["--audit-policy-file"]; ok {
		res.AuditPolicyFile = loadConfigFileMeta(v)
	}
	if v, ok := flags["--authorization-mode"]; ok {
		res.AuthorizationMode = strings.Split(v, ",")
	} else {
		res.AuthorizationMode = strings.Split("AlwaysAllow", ",")
	}
	if v, ok := flags["--bind-address"]; ok {
		res.BindAddress = v
	} else {
		res.BindAddress = "0.0.0.0"
	}
	if v, ok := flags["--client-ca-file"]; ok {
		res.ClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--disable-admission-plugins"]; ok {
		res.DisableAdmissionPlugins = strings.Split(v, ",")
	}
	if v, ok := flags["--enable-admission-plugins"]; ok {
		res.EnableAdmissionPlugins = strings.Split(v, ",")
	}
	if v, ok := flags["--encryption-provider-config"]; ok {
		res.EncryptionProviderConfig = loadEncryptionProviderConfigFileMeta(v)
	}
	if v, ok := flags["--etcd-cafile"]; ok {
		res.EtcdCafile = loadCertFileMeta(v)
	}
	if v, ok := flags["--etcd-certfile"]; ok {
		res.EtcdCertfile = loadCertFileMeta(v)
	}
	if v, ok := flags["--etcd-keyfile"]; ok {
		res.EtcdKeyfile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--kubelet-certificate-authority"]; ok {
		res.KubeletCertificateAuthority = loadCertFileMeta(v)
	}
	if v, ok := flags["--kubelet-client-certificate"]; ok {
		res.KubeletClientCertificate = loadCertFileMeta(v)
	}
	if v, ok := flags["--kubelet-client-key"]; ok {
		res.KubeletClientKey = loadKeyFileMeta(v)
	}
	if v, ok := flags["--profiling"]; ok {
		res.Profiling, _ = strconv.ParseBool(v)
	} else {
		res.Profiling, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--proxy-client-cert-file"]; ok {
		res.ProxyClientCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--proxy-client-key-file"]; ok {
		res.ProxyClientKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--request-timeout"]; ok {
		res.RequestTimeout, _ = time.ParseDuration(v)
	} else {
		res.RequestTimeout, _ = time.ParseDuration("1m0s")
	}
	if v, ok := flags["--requestheader-allowed-names"]; ok {
		res.RequestheaderAllowedNames = strings.Split(v, ",")
	}
	if v, ok := flags["--requestheader-client-ca-file"]; ok {
		res.RequestheaderClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--requestheader-extra-headers-prefix"]; ok {
		res.RequestheaderExtraHeadersPrefix = strings.Split(v, ",")
	}
	if v, ok := flags["--requestheader-group-headers"]; ok {
		res.RequestheaderGroupHeaders = strings.Split(v, ",")
	}
	if v, ok := flags["--requestheader-username-headers"]; ok {
		res.RequestheaderUsernameHeaders = strings.Split(v, ",")
	}
	if v, ok := flags["--secure-port"]; ok {
		res.SecurePort, _ = strconv.Atoi(v)
	} else {
		res.SecurePort, _ = strconv.Atoi("6443")
	}
	if v, ok := flags["--service-account-key-file"]; ok {
		res.ServiceAccountKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--service-account-lookup"]; ok {
		res.ServiceAccountLookup, _ = strconv.ParseBool(v)
	} else {
		res.ServiceAccountLookup, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--tls-cert-file"]; ok {
		res.TlsCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--tls-cipher-suites"]; ok {
		res.TlsCipherSuites = strings.Split(v, ",")
	}
	if v, ok := flags["--tls-private-key-file"]; ok {
		res.TlsPrivateKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--token-auth-file"]; ok {
		res.TokenAuthFile = loadTokenFileMeta(v)
	}
	return &res
}

type K8sKubeSchedulerConfig struct {
	BindAddress                     string             `json:"bindAddress"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ClientCaFile                    *K8sCertFileMeta   `json:"clientCaFile"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Config                          *K8sConfigFileMeta `json:"config"`                          // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Kubeconfig                      *K8sKubeconfigMeta `json:"kubeconfig"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Profiling                       bool               `json:"profiling"`                       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderAllowedNames       []string           `json:"requestheaderAllowedNames"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderClientCaFile       *K8sCertFileMeta   `json:"requestheaderClientCaFile"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderExtraHeadersPrefix []string           `json:"requestheaderExtraHeadersPrefix"` // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderGroupHeaders       []string           `json:"requestheaderGroupHeaders"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderUsernameHeaders    []string           `json:"requestheaderUsernameHeaders"`    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	SecurePort                      int                `json:"securePort"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCertFile                     *K8sCertFileMeta   `json:"tlsCertFile"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCipherSuites                 []string           `json:"tlsCipherSuites"`                 // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsPrivateKeyFile               *K8sKeyFileMeta    `json:"tlsPrivateKeyFile"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
}

func newK8sKubeSchedulerConfig(flags map[string]string) *K8sKubeSchedulerConfig {
	var res K8sKubeSchedulerConfig
	if v, ok := flags["--bind-address"]; ok {
		res.BindAddress = v
	} else {
		res.BindAddress = "0.0.0.0"
	}
	if v, ok := flags["--client-ca-file"]; ok {
		res.ClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--config"]; ok {
		res.Config = loadConfigFileMeta(v)
	}
	if v, ok := flags["--kubeconfig"]; ok {
		res.Kubeconfig = loadKubeconfigMeta(v)
	}
	if v, ok := flags["--profiling"]; ok {
		res.Profiling, _ = strconv.ParseBool(v)
	} else {
		res.Profiling, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--requestheader-allowed-names"]; ok {
		res.RequestheaderAllowedNames = strings.Split(v, ",")
	}
	if v, ok := flags["--requestheader-client-ca-file"]; ok {
		res.RequestheaderClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--requestheader-extra-headers-prefix"]; ok {
		res.RequestheaderExtraHeadersPrefix = strings.Split(v, ",")
	} else {
		res.RequestheaderExtraHeadersPrefix = strings.Split("x-remote-extra-", ",")
	}
	if v, ok := flags["--requestheader-group-headers"]; ok {
		res.RequestheaderGroupHeaders = strings.Split(v, ",")
	} else {
		res.RequestheaderGroupHeaders = strings.Split("x-remote-group", ",")
	}
	if v, ok := flags["--requestheader-username-headers"]; ok {
		res.RequestheaderUsernameHeaders = strings.Split(v, ",")
	} else {
		res.RequestheaderUsernameHeaders = strings.Split("x-remote-user", ",")
	}
	if v, ok := flags["--secure-port"]; ok {
		res.SecurePort, _ = strconv.Atoi(v)
	} else {
		res.SecurePort, _ = strconv.Atoi("10259")
	}
	if v, ok := flags["--tls-cert-file"]; ok {
		res.TlsCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--tls-cipher-suites"]; ok {
		res.TlsCipherSuites = strings.Split(v, ",")
	}
	if v, ok := flags["--tls-private-key-file"]; ok {
		res.TlsPrivateKeyFile = loadKeyFileMeta(v)
	}
	return &res
}

type K8sKubeControllerManagerConfig struct {
	BindAddress                     string             `json:"bindAddress"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ClientCaFile                    *K8sCertFileMeta   `json:"clientCaFile"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Kubeconfig                      *K8sKubeconfigMeta `json:"kubeconfig"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Profiling                       bool               `json:"profiling"`                       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderAllowedNames       []string           `json:"requestheaderAllowedNames"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderClientCaFile       *K8sCertFileMeta   `json:"requestheaderClientCaFile"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderExtraHeadersPrefix []string           `json:"requestheaderExtraHeadersPrefix"` // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderGroupHeaders       []string           `json:"requestheaderGroupHeaders"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RequestheaderUsernameHeaders    []string           `json:"requestheaderUsernameHeaders"`    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RootCaFile                      *K8sCertFileMeta   `json:"rootCaFile"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	SecurePort                      int                `json:"securePort"`                      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ServiceAccountPrivateKeyFile    *K8sKeyFileMeta    `json:"serviceAccountPrivateKeyFile"`    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TerminatedPodGcThreshold        int                `json:"terminatedPodGcThreshold"`        // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCertFile                     *K8sCertFileMeta   `json:"tlsCertFile"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCipherSuites                 []string           `json:"tlsCipherSuites"`                 // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsPrivateKeyFile               *K8sKeyFileMeta    `json:"tlsPrivateKeyFile"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	UseServiceAccountCredentials    bool               `json:"useServiceAccountCredentials"`    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
}

func newK8sKubeControllerManagerConfig(flags map[string]string) *K8sKubeControllerManagerConfig {
	var res K8sKubeControllerManagerConfig
	if v, ok := flags["--bind-address"]; ok {
		res.BindAddress = v
	} else {
		res.BindAddress = "0.0.0.0"
	}
	if v, ok := flags["--client-ca-file"]; ok {
		res.ClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--kubeconfig"]; ok {
		res.Kubeconfig = loadKubeconfigMeta(v)
	}
	if v, ok := flags["--profiling"]; ok {
		res.Profiling, _ = strconv.ParseBool(v)
	} else {
		res.Profiling, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--requestheader-allowed-names"]; ok {
		res.RequestheaderAllowedNames = strings.Split(v, ",")
	}
	if v, ok := flags["--requestheader-client-ca-file"]; ok {
		res.RequestheaderClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--requestheader-extra-headers-prefix"]; ok {
		res.RequestheaderExtraHeadersPrefix = strings.Split(v, ",")
	} else {
		res.RequestheaderExtraHeadersPrefix = strings.Split("x-remote-extra-", ",")
	}
	if v, ok := flags["--requestheader-group-headers"]; ok {
		res.RequestheaderGroupHeaders = strings.Split(v, ",")
	} else {
		res.RequestheaderGroupHeaders = strings.Split("x-remote-group", ",")
	}
	if v, ok := flags["--requestheader-username-headers"]; ok {
		res.RequestheaderUsernameHeaders = strings.Split(v, ",")
	} else {
		res.RequestheaderUsernameHeaders = strings.Split("x-remote-user", ",")
	}
	if v, ok := flags["--root-ca-file"]; ok {
		res.RootCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--secure-port"]; ok {
		res.SecurePort, _ = strconv.Atoi(v)
	} else {
		res.SecurePort, _ = strconv.Atoi("10257")
	}
	if v, ok := flags["--service-account-private-key-file"]; ok {
		res.ServiceAccountPrivateKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--terminated-pod-gc-threshold"]; ok {
		res.TerminatedPodGcThreshold, _ = strconv.Atoi(v)
	} else {
		res.TerminatedPodGcThreshold, _ = strconv.Atoi("12500")
	}
	if v, ok := flags["--tls-cert-file"]; ok {
		res.TlsCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--tls-cipher-suites"]; ok {
		res.TlsCipherSuites = strings.Split(v, ",")
	}
	if v, ok := flags["--tls-private-key-file"]; ok {
		res.TlsPrivateKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--use-service-account-credentials"]; ok {
		res.UseServiceAccountCredentials, _ = strconv.ParseBool(v)
	}
	return &res
}

type K8sKubeProxyConfig struct {
	BindAddress      string             `json:"bindAddress"`      // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Config           *K8sConfigFileMeta `json:"config"`           // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	HostnameOverride string             `json:"hostnameOverride"` // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Kubeconfig       *K8sKubeconfigMeta `json:"kubeconfig"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Profiling        bool               `json:"profiling"`        // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
}

func newK8sKubeProxyConfig(flags map[string]string) *K8sKubeProxyConfig {
	var res K8sKubeProxyConfig
	if v, ok := flags["--bind-address"]; ok {
		res.BindAddress = v
	} else {
		res.BindAddress = "0.0.0.0"
	}
	if v, ok := flags["--config"]; ok {
		res.Config = loadConfigFileMeta(v)
	}
	if v, ok := flags["--hostname-override"]; ok {
		res.HostnameOverride = v
	}
	if v, ok := flags["--kubeconfig"]; ok {
		res.Kubeconfig = loadKubeconfigMeta(v)
	}
	if v, ok := flags["--profiling"]; ok {
		res.Profiling, _ = strconv.ParseBool(v)
	}
	return &res
}

type K8sKubeletConfig struct {
	Address                        string             `json:"address"`                        // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AnonymousAuth                  bool               `json:"anonymousAuth"`                  // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	AuthorizationMode              string             `json:"authorizationMode"`              // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ClientCaFile                   *K8sCertFileMeta   `json:"clientCaFile"`                   // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Config                         *K8sConfigFileMeta `json:"config"`                         // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	HostnameOverride               string             `json:"hostnameOverride"`               // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	Kubeconfig                     *K8sKubeconfigMeta `json:"kubeconfig"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	MakeIptablesUtilChains         bool               `json:"makeIptablesUtilChains"`         // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	PodMaxPids                     int                `json:"podMaxPids"`                     // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	ReadOnlyPort                   int                `json:"readOnlyPort"`                   // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RotateCertificates             bool               `json:"rotateCertificates"`             // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	RotateServerCertificates       bool               `json:"rotateServerCertificates"`       // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	StreamingConnectionIdleTimeout time.Duration      `json:"streamingConnectionIdleTimeout"` // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCertFile                    *K8sCertFileMeta   `json:"tlsCertFile"`                    // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsCipherSuites                []string           `json:"tlsCipherSuites"`                // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
	TlsPrivateKeyFile              *K8sKeyFileMeta    `json:"tlsPrivateKeyFile"`              // versions: v1.26.3, v1.25.8, v1.24.12, v1.23.17
}

func newK8sKubeletConfig(flags map[string]string) *K8sKubeletConfig {
	var res K8sKubeletConfig
	if v, ok := flags["--address"]; ok {
		res.Address = v
	} else {
		res.Address = "0.0.0.0"
	}
	if v, ok := flags["--anonymous-auth"]; ok {
		res.AnonymousAuth, _ = strconv.ParseBool(v)
	} else {
		res.AnonymousAuth, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--authorization-mode"]; ok {
		res.AuthorizationMode = v
	} else {
		res.AuthorizationMode = "AlwaysAllow"
	}
	if v, ok := flags["--client-ca-file"]; ok {
		res.ClientCaFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--config"]; ok {
		res.Config = loadConfigFileMeta(v)
	}
	if v, ok := flags["--hostname-override"]; ok {
		res.HostnameOverride = v
	}
	if v, ok := flags["--kubeconfig"]; ok {
		res.Kubeconfig = loadKubeconfigMeta(v)
	}
	if v, ok := flags["--make-iptables-util-chains"]; ok {
		res.MakeIptablesUtilChains, _ = strconv.ParseBool(v)
	} else {
		res.MakeIptablesUtilChains, _ = strconv.ParseBool("true")
	}
	if v, ok := flags["--pod-max-pids"]; ok {
		res.PodMaxPids, _ = strconv.Atoi(v)
	} else {
		res.PodMaxPids, _ = strconv.Atoi("-1")
	}
	if v, ok := flags["--read-only-port"]; ok {
		res.ReadOnlyPort, _ = strconv.Atoi(v)
	} else {
		res.ReadOnlyPort, _ = strconv.Atoi("10255")
	}
	if v, ok := flags["--rotate-certificates"]; ok {
		res.RotateCertificates, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--rotate-server-certificates"]; ok {
		res.RotateServerCertificates, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--streaming-connection-idle-timeout"]; ok {
		res.StreamingConnectionIdleTimeout, _ = time.ParseDuration(v)
	} else {
		res.StreamingConnectionIdleTimeout, _ = time.ParseDuration("4h0m0s")
	}
	if v, ok := flags["--tls-cert-file"]; ok {
		res.TlsCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--tls-cipher-suites"]; ok {
		res.TlsCipherSuites = strings.Split(v, ",")
	}
	if v, ok := flags["--tls-private-key-file"]; ok {
		res.TlsPrivateKeyFile = loadKeyFileMeta(v)
	}
	return &res
}

type K8sEtcdConfig struct {
	AutoTls            bool             `json:"autoTls"`            // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	CertFile           *K8sCertFileMeta `json:"certFile"`           // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	ClientCertAuth     bool             `json:"clientCertAuth"`     // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	DataDir            *K8sDirMeta      `json:"dataDir"`            // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	KeyFile            *K8sKeyFileMeta  `json:"keyFile"`            // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	PeerAutoTls        bool             `json:"peerAutoTls"`        // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	PeerCertFile       *K8sCertFileMeta `json:"peerCertFile"`       // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	PeerClientCertAuth bool             `json:"peerClientCertAuth"` // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	PeerKeyFile        *K8sKeyFileMeta  `json:"peerKeyFile"`        // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
	TrustedCaFile      *K8sCertFileMeta `json:"trustedCaFile"`      // versions: v3.5.7, v3.4.18, v3.3.17, v3.2.32
}

func newK8sEtcdConfig(flags map[string]string) *K8sEtcdConfig {
	var res K8sEtcdConfig
	if v, ok := flags["--auto-tls"]; ok {
		res.AutoTls, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--cert-file"]; ok {
		res.CertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--client-cert-auth"]; ok {
		res.ClientCertAuth, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--data-dir"]; ok {
		res.DataDir = loadDirMeta(v)
	} else {
		res.DataDir = loadDirMeta("${name}.etcd")
	}
	if v, ok := flags["--key-file"]; ok {
		res.KeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--peer-auto-tls"]; ok {
		res.PeerAutoTls, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--peer-cert-file"]; ok {
		res.PeerCertFile = loadCertFileMeta(v)
	}
	if v, ok := flags["--peer-client-cert-auth"]; ok {
		res.PeerClientCertAuth, _ = strconv.ParseBool(v)
	}
	if v, ok := flags["--peer-key-file"]; ok {
		res.PeerKeyFile = loadKeyFileMeta(v)
	}
	if v, ok := flags["--trusted-ca-file"]; ok {
		res.TrustedCaFile = loadCertFileMeta(v)
	}
	return &res
}
