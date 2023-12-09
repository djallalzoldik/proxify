package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/martian/v3/mitm"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cert *x509.Certificate
	pkey *rsa.PrivateKey
)

const (
	caKeyName     = "cakey.der"
	caCertName    = "cacert.der"
	bits          = 2048
	organization  = "Proxify CA"
	country       = "US"
	province      = "CA"
	locality      = "San Francisco"
	streetAddress = "548 Market St"
	postalCode    = "94104"
)

// GetMitMConfig returns mitm config for martian
func GetMitMConfig() *mitm.Config {
	cfg, err := mitm.NewConfig(cert, pkey)
	if err != nil {
		gologger.Fatal().Msgf("failed to create mitm config")
	}
	return cfg
}

func SaveCAToFile(filename string) error {
	return os.WriteFile(filename, cert.Raw, 0600)
}

func SaveKeyToFile(filename string) error {
	return os.WriteFile(filename, x509.MarshalPKCS1PrivateKey(pkey), 0600)
}

// generateCertificate creates a new certificate
func generateCertificate(certFile, keyFile string) error {
	var err error
	cert, pkey, err = mitm.NewAuthority("Proxify CA", organization, time.Duration(24*365)*time.Hour)
	if err != nil {
		gologger.Fatal().Msgf("failed to generate CA Certificate")
	}
	if err = SaveCAToFile(certFile); err != nil {
		gologger.Fatal().Msgf("failed to save certFile to disk got %v", err)
	}
	if err := SaveKeyToFile(keyFile); err != nil {
		gologger.Fatal().Msgf("failed to write private key to file got %v", err)
	}
	return nil
}

func readCertNKeyFromDisk(certFile, keyFile string) error {
	certBin, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	cert, err = x509.ParseCertificate(certBin)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("expired certificate found")
	}

	keyBin, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	pkey, err = x509.ParsePKCS1PrivateKey(keyBin)
	if err != nil {
		return err
	}

	return nil
}

func LoadCerts(dir string) error {
	certFile := filepath.Join(dir, caCertName)
	keyFile := filepath.Join(dir, caKeyName)

	if !fileutil.FileExists(certFile) || !fileutil.FileExists(keyFile) {
		return generateCertificate(certFile, keyFile)
	}
	if err := readCertNKeyFromDisk(certFile, keyFile); err != nil {
		return fmt.Errorf("malformed/expired certificate found generating new ones\nNote: Certificates must be reinstalled")
	}
	if cert == nil || pkey == nil {
		return errors.New("something went wrong, cannot start proxify")
	}
	return nil
}
