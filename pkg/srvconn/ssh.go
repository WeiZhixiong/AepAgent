package srvconn

import (
	gossh "golang.org/x/crypto/ssh"
	"net"
	"sync"
	"time"
)

var (
	supportedCiphers = []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc",
		"3des-cbc"}

	supportedKexAlgos = []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1", "ecdh-sha2-nistp256", "ecdh-sha2-nistp521",
		"ecdh-sha2-nistp384", "curve25519-sha256@libssh.org",
		"diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256"}

	supportedHostKeyAlgos = []string{
		"ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"ssh-rsa", "ssh-dss",
		"ssh-ed25519", "sk-ssh-ed25519@openssh.com",
	}
)

type SSHClientOptions struct {
	Host         string
	Port         string
	Username     string
	Password     string
	PrivateKey   string
	Passphrase   string
	Timeout      int
	PrivateAuth  gossh.Signer
}

type SSHClient struct {
	*gossh.Client
	Cfg         *SSHClientOptions

	sync.Mutex

	traceSessionMap map[*gossh.Session]time.Time

	refCount int32
}

func (cfg *SSHClientOptions) AuthMethods() []gossh.AuthMethod {
	authMethods := make([]gossh.AuthMethod, 0, 3)
	if cfg.Password != "" {
		authMethods = append(authMethods, gossh.Password(cfg.Password))
	}

	if cfg.PrivateKey != "" {
		var (
			signer gossh.Signer
			err    error
		)
		if cfg.Passphrase != "" {
			// 先使用 passphrase 解析 PrivateKey
			if signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKey),
				[]byte(cfg.Passphrase)); err == nil {
				authMethods = append(authMethods, gossh.PublicKeys(signer))
			}
		}
		if err != nil || cfg.Passphrase == "" {
			// 1. 如果之前使用解析失败，则去掉 passphrase，则尝试直接解析 PrivateKey 防止错误的passphrase
			// 2. 如果没有 Passphrase 则直接解析 PrivateKey
			if signer, err = gossh.ParsePrivateKey([]byte(cfg.PrivateKey)); err == nil {
				authMethods = append(authMethods, gossh.PublicKeys(signer))
			}
		}
	}
	if cfg.PrivateAuth != nil {
		authMethods = append(authMethods, gossh.PublicKeys(cfg.PrivateAuth))
	}

	return authMethods
}

func NewSSHClientWithCfg(cfg *SSHClientOptions) (*SSHClient, error) {
	gosshCfg := gossh.ClientConfig{
		User:              cfg.Username,
		Auth:              cfg.AuthMethods(),
		Timeout:           time.Duration(cfg.Timeout) * time.Second,
		HostKeyCallback:   gossh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: supportedHostKeyAlgos,
		Config: gossh.Config{
			KeyExchanges: supportedKexAlgos,
			Ciphers:      supportedCiphers,
		},
	}
	destAddr := net.JoinHostPort(cfg.Host, cfg.Port)
	gosshClient, err := gossh.Dial("tcp", destAddr, &gosshCfg)
	if err != nil {
		return nil, err
	}
	return &SSHClient{Client: gosshClient, Cfg: cfg,
		traceSessionMap: make(map[*gossh.Session]time.Time)}, nil
}
