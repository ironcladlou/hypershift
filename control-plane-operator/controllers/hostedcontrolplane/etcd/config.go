package etcd

import "time"

type Config struct {
	UnhealthyMemberTTL time.Duration `json:"unhealthy-member-ttl"`

	Etcd     EtcdConfiguration `json:"etcd"`
	ASG      ASGConfig         `json:"asg"`
	Snapshot SnapshotConfig    `json:"snapshot"`
}

// EtcdConfiguration contains the configuration related to the underlying etcd
// server.
type EtcdConfiguration struct {
	AdvertiseAddress        string              `json:"advertise-address"`
	DataDir                 string              `json:"data-dir"`
	ClientTransportSecurity SecurityConfig      `json:"client-transport-security"`
	PeerTransportSecurity   SecurityConfig      `json:"peer-transport-security"`
	BackendQuota            int64               `json:"backend-quota"`
	AutoCompactionMode      string              `json:"auto-compaction-mode"`
	AutoCompactionRetention string              `json:"auto-compaction-retention"`
	InitACL                 *ACLConfig          `json:"init-acl,omitempty"`
	JWTAuthTokenConfig      *JWTAuthTokenConfig `json:"jwt-auth-token-config,omitempty"`
}

type SecurityConfig struct {
	CertFile      string `json:"cert-file"`
	KeyFile       string `json:"key-file"`
	CertAuth      bool   `json:"client-cert-auth"`
	TrustedCAFile string `json:"trusted-ca-file"`
	AutoTLS       bool   `json:"auto-tls"`
}

// ACLConfig defines the acl configuration for etcd,
// which will be applied to the etcd during provisioning.
// --client-cert-auth must be set to true.
type ACLConfig struct {
	RootPassword *string `json:"rootPassword,omitempty"`
	Roles        []Role  `json:"roles"`
	Users        []User  `json:"users"`
}

// JWTAuthTokenConfig defines the config for the JWT auth token.
type JWTAuthTokenConfig struct {
	SignMethod     string `json:"sign-method"`
	PrivateKeyFile string `json:"private-key-file"`
	PublicKeyFile  string `json:"public-key-file"`
	TTL            string `json:"ttl"`
}

// Role defines an etcd ACL role with its permissions.
type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// Users defines an etcd ACL user with its password(optional) and binding roles.
type User struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

// Permission defines the permission.
type Permission struct {
	Mode     string `json:"mode"`
	Key      string `json:"key"`
	RangeEnd string `json:"rangeEnd"`
	Prefix   bool   `json:"prefix"`
}

// Config represents the configuration of the auto-scaling group provider.
type ASGConfig struct {
	Provider string                 `json:"provider"`
	Params   map[string]interface{} `json:",inline"`
}

// Config represents the configuration of the snapshot provider.
type SnapshotConfig struct {
	Interval time.Duration `json:"interval"`
	TTL      time.Duration `json:"ttl"`

	Provider string                 `json:"provider"`
	Params   map[string]interface{} `json:",inline"`
}
