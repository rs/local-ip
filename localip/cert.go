package localip

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type CertManager struct {
	Email  string
	Reg    string
	Key    []byte
	Domain string
	Cache  Cache

	client *lego.Client

	mu            sync.RWMutex
	dnsChallenges map[string][]string
	certPem       []byte
	keyPem        []byte
	cert          *tls.Certificate
}

func (c *CertManager) GetEmail() string {
	return c.Email
}

func (c *CertManager) GetRegistration() *registration.Resource {
	return &registration.Resource{
		URI: c.Reg,
	}
}

func (c *CertManager) GetPrivateKey() crypto.PrivateKey {
	block, _ := pem.Decode(c.Key)
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func (c *CertManager) Init(p challenge.Provider) error {
	config := lego.NewConfig(c)
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	err = client.Challenge.SetDNS01Provider(p)
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *CertManager) loadOrRefresh() {
	if err := c.readCache(); err != nil {
		log.Printf("readCache: %v", err)
	}
	if c.needsRefresh() {
		if err := c.Obtain(); err != nil {
			log.Printf("Obtain: %v", err)
			return
		}
		if err := c.saveCache(); err != nil {
			log.Printf("saveCache: %v", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	cert, err := tls.X509KeyPair(c.certPem, c.keyPem)
	if err != nil {
		log.Printf("loadOrRefresh: %v", err)
	}
	c.cert = &cert
}

func (c *CertManager) needsRefresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.certPem) == 0 || len(c.keyPem) == 0 {
		return true
	}

	cert, err := tls.X509KeyPair(c.certPem, c.keyPem)
	if err != nil {
		return true
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Since(x509Cert.NotAfter) > -15*24*time.Hour
}

func (c *CertManager) readCache() (err error) {
	c.certPem, err = c.Cache.Get("cert.pem")
	if err != nil {
		return err
	}
	c.keyPem, _ = c.Cache.Get("key.pem")
	return err
}

func (c *CertManager) saveCache() (err error) {
	err = c.Cache.Put("cert.pem", c.certPem)
	if err != nil {
		return err
	}
	return c.Cache.Put("key.pem", c.keyPem)
}

func (c *CertManager) Obtain() error {
	request := certificate.ObtainRequest{
		Domains: []string{"*." + c.Domain, c.Domain},
		Bundle:  true,
	}
	res, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certPem = res.Certificate
	c.keyPem = res.PrivateKey
	return nil
}
func (c *CertManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}
