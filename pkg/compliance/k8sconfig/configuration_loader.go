// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package k8sconfig

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"gopkg.in/yaml.v3"
)

const (
	k8sManifestsDir   = "/etc/kubernetes/manifests"
	k8sKubeconfigsDir = "/etc/kubernetes"
)

type K8sNodeConfig struct {
	SystemServices struct {
		Kubelet *K8sConfigFileMeta
	} `json:"service"`

	Kubeconfigs struct {
		Admin *K8sKubeconfigMeta `json:"admin"`
	} `json:"kubeconfigs"`

	Components struct {
		Etcd                  *K8sEtcdConfig                  `json:"etcd"`
		KubeApiserver         *K8sKubeApiserverConfig         `json:"kubeApiserver"`
		KubeControllerManager *K8sKubeControllerManagerConfig `json:"kubeControllerManager"`
		Kubelet               *K8sKubeletConfig               `json:"kubelet"`
		KubeProxy             *K8sKubeProxyConfig             `json:"kubeProxy"`
		KubeScheduler         *K8sKubeSchedulerConfig         `json:"kubeScheduler"`
	} `json:"components"`

	Manifests struct {
		Etcd                 *K8sConfigFileMeta `json:"etcd"`
		KubeContollerManager *K8sConfigFileMeta `json:"kubeContollerManager"`
		KubeApiserver        *K8sConfigFileMeta `json:"kubeApiserver"`
		KubeScheduler        *K8sConfigFileMeta `json:"kubeScheduler"`
	} `json:"manifests"`
}

type K8sDirMeta struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

type K8sConfigFileMeta struct {
	Path    string      `json:"path"`
	Mode    uint32      `json:"mode"`
	Content interface{} `json:"content"`
}

type K8sTokenFileMeta struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

type K8sKubeconfigMeta struct {
	Path       string      `json:"path,omitempty"`
	Mode       uint32      `json:"mode,omitempty"`
	Kubeconfig interface{} `json:"kubeconfig"`
}

type K8sKeyFileMeta struct {
	Path string `json:"path,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
	Key  struct {
		PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	} `json:"key"`
}

type K8sCertFileMeta struct {
	Path        string `json:"path,omitempty"`
	Mode        uint32 `json:"mode,omitempty"`
	Certificate struct {
		Fingerprint    string    `json:"fingerprint"`
		SerialNumber   string    `json:"serialNumber,omitempty"`
		SubjectKeyId   string    `json:"subjectKeyId,omitempty"`
		AuthorityKeyId string    `json:"authorityKeyId,omitempty"`
		CommonName     string    `json:"commonName"`
		Organization   []string  `json:"organization,omitempty"`
		DNSNames       []string  `json:"dnsNames,omitempty"`
		IPAddresses    []net.IP  `json:"ipAddresses,omitempty"`
		NotAfter       time.Time `json:"notAfter"`
		NotBefore      time.Time `json:"notBefore"`
	} `json:"certificate"`
}

// k8SKubeconfigSource is used to parse the kubeconfig files. It is not
// exported as-is, and used to build K8sKubeconfig.
// https://github.com/kubernetes/kubernetes/blob/ad18954259eae3db51bac2274ed4ca7304b923c4/staging/src/k8s.io/client-go/tools/clientcmd/api/types.go#LL31C1-L55C2
type (
	k8SKubeconfigSource struct {
		Kind       string `yaml:"kind,omitempty"`
		APIVersion string `yaml:"apiVersion,omitempty"`

		Clusters []struct {
			Name    string                     `yaml:"name"`
			Cluster k8sKubeconfigClusterSource `yaml:"cluster"`
		} `yaml:"clusters"`

		Users []struct {
			Name string                  `yaml:"name"`
			User k8sKubeconfigUserSource `yaml:"user"`
		} `yaml:"users"`

		Contexts []struct {
			Name    string                     `yaml:"name"`
			Context k8sKubeconfigContextSource `yaml:"context"`
		} `yaml:"contexts"`

		CurrentContext string `yaml:"current-context"`
	}

	k8sKubeconfigClusterSource struct {
		Server                   string `yaml:"server"`
		TLSServerName            string `yaml:"tls-server-name,omitempty"`
		InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
		CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
		CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
		ProxyURL                 string `yaml:"proxy-url,omitempty"`
		DisableCompression       bool   `yaml:"disable-compression,omitempty"`
	}

	k8sKubeconfigUserSource struct {
		ClientCertificate     string `yaml:"client-certificate,omitempty"`
		ClientCertificateData string `yaml:"client-certificate-data,omitempty"`
		ClientKey             string `yaml:"client-key,omitempty"`
		ClientKeyData         string `yaml:"client-key-data,omitempty" datapolicy:"security-key"`
		Token                 string `yaml:"token,omitempty" datapolicy:"token"`
		TokenFile             string `yaml:"tokenFile,omitempty"`
		Username              string `yaml:"username,omitempty"`
		Password              string `yaml:"password,omitempty" datapolicy:"password"`
	}

	k8sKubeconfigContextSource struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	}

	K8SKubeconfig struct {
		Clusters       map[string]*K8sKubeconfigCluster `json:"clusters"`
		Users          map[string]*K8sKubeconfigUser    `json:"users"`
		Contexts       map[string]*K8sKubeconfigContext `json:"contexts"`
		CurrentContext string                           `json:"currentContext"`
	}

	K8sKubeconfigCluster struct {
		Server                string           `json:"server"`
		TLSServerName         string           `json:"tlsServerName,omitempty"`
		InsecureSkipTLSVerify bool             `json:"insecureSkipTlsVerify,omitempty"`
		CertificateAuthority  *K8sCertFileMeta `json:"certificateAuthority,omitempty"`
		ProxyURL              string           `json:"proxyUrl,omitempty"`
		DisableCompression    bool             `json:"disableCompression,omitempty"`
	}

	K8sKubeconfigUser struct {
		UseToken          bool             `json:"useToken"`
		UsePassword       bool             `json:"usePassword"`
		ClientCertificate *K8sCertFileMeta `json:"clientCertificate,omitempty"`
		ClientKey         *K8sKeyFileMeta  `json:"clientKey,omitempty"`
	}

	K8sKubeconfigContext struct {
		Cluster   string `json:"cluster"`
		User      string `json:"user"`
		Namespace string `json:"namespace,omitempty"`
	}
)

// https://github.com/kubernetes/kubernetes/blob/e1ad9bee5bba8fbe85a6bf6201379ce8b1a611b1/staging/src/k8s.io/apiserver/pkg/apis/config/types.go#L70
type (
	K8sEncryptionProviderConfigFileMeta struct {
		Path      string `json:"path,omitempty"`
		Mode      uint32 `json:"mode,omitempty"`
		Resources []struct {
			Resources []string `yaml:"resources" json:"resources"`
			Providers []struct {
				AESGCM    *K8sEncryptionProviderKeysSource `yaml:"aesgcm,omitempty" json:"aesgcm,omitempty"`
				AESCBC    *K8sEncryptionProviderKeysSource `yaml:"aescbc,omitempty" json:"aescbc,omitempty"`
				Secretbox *K8sEncryptionProviderKeysSource `yaml:"secretbox,omitempty" json:"secretbox,omitempty"`
				Identity  *struct{}                        `yaml:"identity,omitempty" json:"identity,omitempty"`
				KMS       *K8sEncryptionProviderKMSSource  `yaml:"kms,omitempty" json:"kms,omitempty"`
			} `yaml:"providers" json:"providers"`
		} `yaml:"resources" json:"resources"`
	}

	K8sEncryptionProviderKMSSource struct {
		Name      string `yaml:"name" json:"name"`
		Endpoint  string `yaml:"endpoint" json:"endpoint"`
		CacheSize int    `yaml:"cachesize" json:"cachesize"`
		Timeout   string `yaml:"timeout" json:"timeout"`
	}

	K8sEncryptionProviderKeysSource struct {
		Keys []struct {
			Name string `yaml:"name" json:"name"`
		} `yaml:"keys" json:"keys"`
	}
)

func LoadConfiguration(ctx context.Context, hostroot string) *K8sNodeConfig {
	// TODO: can we extract the staticPodPath to resolve the manifests instead of hardcoding
	node := K8sNodeConfig{}

	pathJoin := func(dir, path string) string {
		return filepath.Join(hostroot, dir, path)
	}

	node.SystemServices.Kubelet = loadServiceFileMeta([]string{
		pathJoin("/etc/systemd/system/kubelet.service.d", "10-kubeadm.conf"),
		pathJoin("/usr/lib/systemd/system", "kubelet.service"),
		pathJoin("/lib/systemd/system", "kubelet.service"),
	})

	node.Kubeconfigs.Admin = loadKubeconfigMeta(pathJoin(k8sKubeconfigsDir, "admin.conf"))

	node.Manifests.KubeApiserver = loadConfigFileMeta(pathJoin(k8sManifestsDir, "kube-apiserver.yaml"))
	node.Manifests.KubeContollerManager = loadConfigFileMeta(pathJoin(k8sManifestsDir, "kube-controller-manager.yaml"))
	node.Manifests.KubeScheduler = loadConfigFileMeta(pathJoin(k8sManifestsDir, "kube-scheduler.yaml"))
	node.Manifests.Etcd = loadConfigFileMeta(pathJoin(k8sManifestsDir, "etcd.yaml"))

	procs, err := process.ProcessesWithContext(ctx)
	if err == nil {
		for _, p := range procs {
			name, _ := p.Name()
			switch name {
			case "etcd":
				node.Components.Etcd = newK8sEtcdConfig(getCmdlineFlags(p))
			case "kube-apiserver", "apiserver":
				node.Components.KubeApiserver = newK8sKubeApiserverConfig(getCmdlineFlags(p))
			case "kube-controller-manager", "kube-controller", "controller-manager":
				node.Components.KubeControllerManager = newK8sKubeControllerManagerConfig(getCmdlineFlags(p))
			case "kube-scheduler":
				node.Components.KubeScheduler = newK8sKubeSchedulerConfig(getCmdlineFlags(p))
			case "kubelet":
				node.Components.Kubelet = newK8sKubeletConfig(getCmdlineFlags(p))
			case "kube-proxy":
				node.Components.KubeProxy = newK8sKubeProxyConfig(getCmdlineFlags(p))
			}
		}
	}

	return &node
}

func loadMeta(name string, loadContent bool) (os.FileInfo, []byte, bool) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, nil, false
	}
	if loadContent && info.IsDir() {
		return nil, nil, false
	}
	var b []byte
	const maxSize = 64 * 1024
	if loadContent && info.Size() < maxSize {
		if f, err := os.Open(name); err == nil {
			b, _ = ioutil.ReadAll(io.LimitReader(f, maxSize))
		}
	}
	return info, b, true
}

func loadDirMeta(name string) *K8sDirMeta {
	info, _, ok := loadMeta(name, false)
	if !ok {
		return nil
	}
	return &K8sDirMeta{
		Path: name,
		Mode: uint32(info.Mode()),
	}
}

func loadServiceFileMeta(names []string) *K8sConfigFileMeta {
	for _, name := range names {
		meta := loadConfigFileMeta(name)
		if meta != nil {
			return meta
		}
	}
	return nil
}

func loadConfigFileMeta(name string) *K8sConfigFileMeta {
	info, b, ok := loadMeta(name, true)
	if !ok {
		return nil
	}
	var content interface{}
	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
		if err := yaml.Unmarshal(b, &content); err != nil {
			content = b
		}
	} else {
		content = string(b)
	}
	return &K8sConfigFileMeta{
		Path:    name,
		Mode:    uint32(info.Mode()),
		Content: content,
	}
}

func loadEncryptionProviderConfigFileMeta(name string) *K8sEncryptionProviderConfigFileMeta {
	info, b, ok := loadMeta(name, true)
	if !ok {
		return nil
	}
	var content K8sEncryptionProviderConfigFileMeta
	if err := yaml.Unmarshal(b, &content); err != nil {
		return nil
	}
	content.Path = name
	content.Mode = uint32(info.Mode())
	return &content
}

func loadTokenFileMeta(name string) *K8sTokenFileMeta {
	info, _, ok := loadMeta(name, false)
	if !ok {
		return nil
	}
	return &K8sTokenFileMeta{
		Path: name,
		Mode: uint32(info.Mode()),
	}
}

const (
	ECPrivateKeyBlockType  = "EC PRIVATE KEY"
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	PrivateKeyBlockType    = "PRIVATE KEY"
	PublicKeyBlockType     = "PUBLIC KEY"
	CertificateBlockType   = "CERTIFICATE"
)

func loadKeyFileMeta(name string) *K8sKeyFileMeta {
	info, keyData, ok := loadMeta(name, true)
	if !ok {
		return nil
	}
	meta := parseKeyData(keyData)
	meta.Path = name
	meta.Mode = uint32(info.Mode())
	return meta
}

func parseKeyData(keyData []byte) *K8sKeyFileMeta {
	var pub crypto.PublicKey
	var keyPemBlock *pem.Block
	for {
		keyPemBlock, keyData = pem.Decode(keyData)
		if keyPemBlock == nil {
			break
		}
		switch keyPemBlock.Type {
		case ECPrivateKeyBlockType:
			// ECDSA Private Key in ASN.1 format
			if key, err := x509.ParseECPrivateKey(keyPemBlock.Bytes); err == nil {
				pub = key.Public()
			}
		case RSAPrivateKeyBlockType:
			// RSA Private Key in PKCS#1 format
			if key, err := x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes); err == nil {
				pub = key.Public()
			}
		case PrivateKeyBlockType:
			// RSA or ECDSA Private Key in unencrypted PKCS#8 format
			if key, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes); err == nil {
				switch k := key.(type) {
				case *rsa.PrivateKey:
					pub = k.Public()
				case *ecdsa.PrivateKey:
					pub = k.Public()
				case ed25519.PrivateKey:
					pub = k.Public()
				}
			}
			// RSA or ECDSA Public Key in PKIX format
		case PublicKeyBlockType:
			if key, err := x509.ParsePKIXPublicKey(keyPemBlock.Bytes); err == nil {
				pub = key
			}
		}
	}
	var data K8sKeyFileMeta
	data.Key.PublicKeyFingerprint = publicKeyFingerprint(pub)
	return &data
}

// https://github.com/kubernetes/kubernetes/blob/ad18954259eae3db51bac2274ed4ca7304b923c4/cmd/kubeadm/test/kubeconfig/util.go#L77-L87
func loadCertFileMeta(name string) *K8sCertFileMeta {
	info, certData, ok := loadMeta(name, true)
	if !ok {
		return nil
	}
	meta := parseCertData(certData)
	meta.Path = name
	meta.Mode = uint32(info.Mode())
	return meta
}

func parseCertData(certData []byte) *K8sCertFileMeta {
	certPemBlock, _ := pem.Decode(certData)
	if certPemBlock == nil {
		return nil
	}
	if certPemBlock.Type != CertificateBlockType {
		return nil
	}
	c, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return nil
	}
	sn := c.SerialNumber.String()
	if sn == "0" {
		sn = ""
	}

	h256 := sha256.New()
	h256.Write(certPemBlock.Bytes)

	var data K8sCertFileMeta
	data.Certificate.Fingerprint = printSHA256Fingerprint(h256.Sum(nil))
	data.Certificate.SerialNumber = sn
	data.Certificate.SubjectKeyId = printColumnSeparatedHex(c.SubjectKeyId)
	data.Certificate.AuthorityKeyId = printColumnSeparatedHex(c.AuthorityKeyId)
	data.Certificate.CommonName = c.Subject.CommonName
	data.Certificate.Organization = c.Subject.Organization
	data.Certificate.DNSNames = c.DNSNames
	data.Certificate.IPAddresses = c.IPAddresses
	data.Certificate.NotAfter = c.NotAfter
	data.Certificate.NotBefore = c.NotBefore
	return &data
}

func loadKubeconfigMeta(name string) *K8sKubeconfigMeta {
	info, b, ok := loadMeta(name, true)
	if !ok {
		return nil
	}

	var source k8SKubeconfigSource
	var err error
	switch filepath.Ext(name) {
	case ".json":
		err = json.Unmarshal(b, &source)
	default:
		err = yaml.Unmarshal(b, &source)
	}
	if err != nil {
		return nil
	}

	content := &K8SKubeconfig{
		Clusters: make(map[string]*K8sKubeconfigCluster),
		Users:    make(map[string]*K8sKubeconfigUser),
		Contexts: make(map[string]*K8sKubeconfigContext),
	}
	for _, cluster := range source.Clusters {
		var certAuth *K8sCertFileMeta
		if certAuthDataB64 := cluster.Cluster.CertificateAuthorityData; certAuthDataB64 != "" {
			if certAuthData, err := base64.StdEncoding.DecodeString(certAuthDataB64); err == nil {
				certAuth = parseCertData(certAuthData)
			}
		} else if certAuthFile := cluster.Cluster.CertificateAuthority; certAuthFile != "" {
			certAuth = loadCertFileMeta(certAuthFile)
		}
		content.Clusters[cluster.Name] = &K8sKubeconfigCluster{
			Server:                cluster.Cluster.Server,
			TLSServerName:         cluster.Cluster.TLSServerName,
			InsecureSkipTLSVerify: cluster.Cluster.InsecureSkipTLSVerify,
			CertificateAuthority:  certAuth,
			ProxyURL:              cluster.Cluster.ProxyURL,
			DisableCompression:    cluster.Cluster.DisableCompression,
		}
	}
	for _, user := range source.Users {
		var clientCert *K8sCertFileMeta
		var clientKey *K8sKeyFileMeta
		if clientCertDataB64 := user.User.ClientCertificateData; clientCertDataB64 != "" {
			if clientCertDataB64, err := base64.StdEncoding.DecodeString(clientCertDataB64); err == nil {
				clientCert = parseCertData(clientCertDataB64)
			}
		} else if clientCertFile := user.User.ClientCertificate; clientCertFile != "" {
			clientCert = loadCertFileMeta(clientCertFile)
		}
		if clientKeyDataB64 := user.User.ClientKeyData; clientKeyDataB64 != "" {
			if clientKeyDataB64, err := base64.StdEncoding.DecodeString(clientKeyDataB64); err == nil {
				clientKey = parseKeyData(clientKeyDataB64)
			}
		} else if clientKeyFile := user.User.ClientKey; clientKeyFile != "" {
			clientKey = loadKeyFileMeta(clientKeyFile)
		}
		content.Users[user.Name] = &K8sKubeconfigUser{
			UseToken:          user.User.TokenFile != "" || user.User.Token != "",
			ClientCertificate: clientCert,
			ClientKey:         clientKey,
		}
	}
	for _, context := range source.Contexts {
		content.Contexts[context.Name] = &K8sKubeconfigContext{
			Cluster:   context.Context.Cluster,
			User:      context.Context.User,
			Namespace: context.Context.Namespace,
		}
	}

	return &K8sKubeconfigMeta{
		Path:       name,
		Mode:       uint32(info.Mode()),
		Kubeconfig: content,
	}
}

func publicKeyFingerprint(pub crypto.PublicKey) string {
	if pub == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write(der)
	return printSHA256Fingerprint(h.Sum(nil))
}

// in OpenSSH >= 2.6, a fingerprint is now displayed as base64 SHA256.
func printSHA256Fingerprint(f []byte) string {
	return fmt.Sprintf("SHA256:%s", strings.TrimSuffix(base64.StdEncoding.EncodeToString(f), "="))
}

func printColumnSeparatedHex(d []byte) string {
	h := strings.ToUpper(hex.EncodeToString(d))
	var sb strings.Builder
	for i, r := range h {
		sb.WriteRune(r)
		if i%2 == 1 && i != len(h)-1 {
			sb.WriteRune(':')
		}
	}
	return sb.String()
}

func getCmdlineFlags(p *process.Process) map[string]string {
	flagsMap := make(map[string]string, 0)
	cmdline, err := p.CmdlineSlice()
	if err != nil {
		return flagsMap
	}
	pendingFlagValue := false
	for i, arg := range cmdline {
		if strings.HasPrefix(arg, "-") {
			parts := strings.SplitN(arg, "=", 2)
			// We have -xxx=yyy, considering the flag completely resolved
			if len(parts) == 2 {
				flagsMap[parts[0]] = parts[1]
			} else {
				flagsMap[parts[0]] = ""
				pendingFlagValue = true
			}
		} else {
			if pendingFlagValue {
				flagsMap[cmdline[i-1]] = arg
			} else {
				flagsMap[arg] = ""
			}
		}
	}
	return flagsMap
}
