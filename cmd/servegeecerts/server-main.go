/*

Copyright 2019 Continusec Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"

	"golang.org/x/net/context"

	"github.com/continusec/geecert"
	pb "github.com/continusec/geecert/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"net/http"

	"golang.org/x/crypto/ssh"

	"github.com/dmksnnk/sentryhook"
	"github.com/getsentry/raven-go"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/meatballhat/negroni-logrus"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

type SSOServer struct {
	Config *pb.ServerConfig

	Validator geecert.IDTokenValidator
}

// Generate a host cert for whatever we see
func (s *SSOServer) makeHostCert(w http.ResponseWriter, h string) {
	var certToReturn []byte
	var kt string
	var earlyFailError = errors.New("fail now please")

	if len(h) == 0 {
		log.Infof("No hostname specified: %s", h)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Derived from ssh.common.supportedHostKeyAlgos with certificate host key types removed
	var supportedHostKeyAlgos = []string{
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA, ssh.KeyAlgoDSA, ssh.KeyAlgoED25519,
	}
	_, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", h, s.Config.SshConnectForPublickeyPort), &ssh.ClientConfig{
		User: "ca",
		Auth: []ssh.AuthMethod{
			ssh.Password("wrongpassignoreme"),
		},
		HostKeyAlgorithms: supportedHostKeyAlgos,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if key == nil {
				return errors.New("no host key")
			}
			caKey, err := LoadPrivateKeyFromPEM(s.Config.CaKeyPath)
			if err != nil {
				log.Errorf("Error LoadPrivateKeyFromPEM for hostname %s: ", h, err)
				return err
			}

			cert, nva, err := CreateHostCertificate(h, key, caKey, time.Duration(s.Config.GenerateCertDurationSeconds)*time.Second)
			if err != nil || cert == nil {
				log.Errorf("Error CreateHostCertificate for hostname %s: ", h, err)
				return err
			}
			kt = key.Type()

			log.Infof("Issued host certificate for %s valid until %s.\n", h, nva.Format(time.RFC3339))

			certToReturn = cert
			return earlyFailError
		},
	})
	if err != nil && !strings.Contains(err.Error(), "fail now please") {
		log.Warnf("Error SSH connecting to hostname %s on port %d: %s ", h, s.Config.SshConnectForPublickeyPort, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	} else if len(certToReturn) == 0 {
		log.WithField("hostname", h).Errorf("Error using SSH to retrieve certificate for hostname: %s", h)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%s-cert-v01@openssh.com %s %s\n", kt, base64.StdEncoding.EncodeToString(certToReturn), h)
}

func (s *SSOServer) issueHostCertificate(w http.ResponseWriter, r *http.Request) {

	h := r.FormValue("host")
	// Exclude monitoring http requests from logging
	if r.UserAgent() != "Go-http-client/1.1" && h != "" {
		log.Infof("Received issueHostCertificate from %s with user agent %s", r.RemoteAddr, r.UserAgent())
	}
	for _, m := range s.Config.AllowedHosts {
		matched, err := filepath.Match(m, h)
		if err != nil {
			log.Infof("Error matching hostname: %s", h)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if matched {
			s.makeHostCert(w, h)
			return
		}
	}
	// Exclude monitoring http requests from logging
	if r.UserAgent() != "Go-http-client/1.1" && h != "" {
		log.Warnf("Hostname: %s did not match AllowedHosts", h)
	}
	w.WriteHeader(http.StatusBadRequest)
	return
}

func (s *SSOServer) StartHTTP() {

	mux := http.NewServeMux()
	mux.HandleFunc("/hostCertificate", raven.RecoveryHandler(s.issueHostCertificate))
	var err error
	if s.Config.HostSigningTlsPath == "" { // http
		n := negroni.New()
		nl := negronilogrus.NewMiddlewareFromLogger(log.StandardLogger(), "web")
		nl.Before = func(entry *log.Entry, req *http.Request, remoteAddr string) *log.Entry {
			return entry.WithFields(log.Fields{
				"request":   req.RequestURI,
				"hostname":  req.Host,
				"userAgent": req.UserAgent(),
				"method":    req.Method,
				"remote":    remoteAddr,
			})
		}
		n.Use(nl)
		n.Use(negroni.NewRecovery())
		n.UseHandler(mux)
		n.Run(fmt.Sprintf(":%d", s.Config.HttpListenPort))
	} else {
		err = http.ListenAndServeTLS(fmt.Sprintf(":%d", s.Config.HttpListenPort), s.Config.HostSigningTlsPath, s.Config.HostSigningTlsPath, mux)
	}
	if err != nil {
		log.Errorf("Error starting HTTP server: %s", err)
	}

}

func (s *SSOServer) GetSSHCerts(ctx context.Context, in *pb.SSHCertsRequest) (*pb.SSHCertsResponse, error) {
	idTokenClaims, err := s.Validator.ValidateIDToken(in.IdToken)
	// use lowercase of user claimed email
	userEmail := strings.ToLower(idTokenClaims.EmailAddress)
	if err != nil {
		log.WithContext(ctx).WithField("emailAddress", idTokenClaims.EmailAddress).Errorf("Error in ValidateIDToken for %s", idTokenClaims.EmailAddress)
		return nil, err
	}

	userConf, ok := s.Config.AllowedUsers[userEmail]
	if !ok {
		log.WithContext(ctx).WithField("emailAddress", idTokenClaims.EmailAddress).Errorf("No certificates allowed for %s", idTokenClaims.EmailAddress)
		return &pb.SSHCertsResponse{
			Status: pb.ResponseCode_NO_CERTS_ALLOWED,
		}, nil
	}

	rpk, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil {
		return nil, err
	}

	keyToSign, err := ssh.ParsePublicKey(rpk)
	if err != nil {
		return nil, err
	}

	caKey, err := LoadPrivateKeyFromPEM(s.Config.CaKeyPath)
	if err != nil {
		return nil, err
	}

	ourCAPubKey, err := ssh.NewPublicKey(&caKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// Use map to de-dupe
	principals := make(map[string]interface{})
	knownHosts := make(map[string]interface{})
	perms := make(map[string]string)
	var sshConfig []string
	for _, up := range userConf.Profiles {
		p, ok := s.Config.UserProfiles[up]
		if !ok {
			log.WithContext(ctx).WithField("emailAddress", idTokenClaims.EmailAddress).Warnf("Warning, profile not found for user (ignoring): %s", up)
			continue
		}
		for _, pp := range p.Principals {
			principals[pp] = nil
		}
		for _, pp := range p.KnownHosts {
			knownHosts[pp] = nil
		}
		for k, v := range p.CertPermissions {
			perms[k] = v // last one wins - usually these are blank anyway
		}
		sshConfig = append(sshConfig, p.SshConfigLines...)
	}
	var principalList []string
	for key := range principals {
		principalList = append(principalList, key)
	}
	var knownHostsFile []string
	for kh := range knownHosts {
		knownHostsFile = append(knownHostsFile, fmt.Sprintf("@cert-authority %s ssh-rsa %s %s",
			kh,
			base64.StdEncoding.EncodeToString(ourCAPubKey.Marshal()),
			s.Config.CaComment,
		))
	}

	cert, nva, err := CreateUserCertificate(principalList, idTokenClaims.EmailAddress, keyToSign, caKey, time.Duration(s.Config.GenerateCertDurationSeconds)*time.Second, perms)
	if err != nil {
		log.WithContext(ctx).WithField("emailAddress", idTokenClaims.EmailAddress).
			Error("Error in CreateUserCertificate for %s", idTokenClaims.EmailAddress)
		return nil, err
	}

	log.WithContext(ctx).WithField("emailAddress", idTokenClaims.EmailAddress).
		Infof("Issued user certificate to %s valid until %s.\n", idTokenClaims.EmailAddress, nva.Format(time.RFC3339))

	return &pb.SSHCertsResponse{
		Status:                 pb.ResponseCode_OK,
		Certificate:            fmt.Sprintf("ssh-rsa-cert-v01@openssh.com %s %s\n", base64.StdEncoding.EncodeToString(cert), idTokenClaims.EmailAddress),
		CertificateAuthorities: knownHostsFile,
		Config:                 sshConfig,
	}, nil
}

func LoadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("Bad PEM")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Unexpected block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// FingerprintSHA512 returns the user presentation of the key's
// fingerprint as unpadded base64 encoded sha512 hash.
// This format was introduced from OpenSSH 7.2.
// http://www.openssh.com/txt/release-7.2
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func FingerprintSHA512(pubKey ssh.PublicKey) string {
	sha512sum := sha512.Sum512(pubKey.Marshal())
	hash := base64.RawStdEncoding.EncodeToString(sha512sum[:])
	return "SHA512:" + hash
}

func CreateHostCertificate(hostname string, keyToSign ssh.PublicKey, signingKey *rsa.PrivateKey, duration time.Duration) ([]byte, *time.Time, error) {
	signer, err := ssh.NewSignerFromKey(signingKey)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	end := now.Add(duration)
	cert := ssh.Certificate{
		Key:             keyToSign,
		CertType:        ssh.HostCert,
		KeyId:           hostname,
		ValidPrincipals: []string{hostname},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(end.Unix()),
	}
	if keyToSign.Type() == ssh.CertAlgoECDSA256v01 {
		log.WithField("hostname", hostname).Errorf("CreateHostCertificate error: Attempted to sign a signature, not a host key for: %s key: %s type: %s",
			hostname, FingerprintSHA512(keyToSign), keyToSign.Type())
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"hostname":       hostname,
				"keyFingerprint": FingerprintSHA512(keyToSign),
				"keyType":        keyToSign.Type(),
			}).Error("CreateHostCertificate SignCert panic'd, might have connected to a bad SSH server with bad host key")
		}
	}()
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return nil, nil, err
	}
	log.WithField("hostname", hostname).Infof("Signed a host key for: %s key: %s type: %s", hostname, FingerprintSHA512(keyToSign), keyToSign.Type())
	log.WithField("hostname", hostname).Infof("Signature of host key for: %s key: %s type: %s", hostname, FingerprintSHA512(cert.SignatureKey), cert.Type())
	return cert.Marshal(), &end, nil
}

func CreateUserCertificate(usernames []string, emailAddress string, keyToSign ssh.PublicKey, signingKey *rsa.PrivateKey, duration time.Duration, perms map[string]string) ([]byte, *time.Time, error) {
	signer, err := ssh.NewSignerFromKey(signingKey)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	end := now.Add(duration)
	cert := ssh.Certificate{
		Key:             keyToSign,
		CertType:        ssh.UserCert,
		KeyId:           strings.Join(usernames, "/") + " (for " + emailAddress + ")",
		ValidPrincipals: usernames,
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(end.Unix()),
		Permissions: ssh.Permissions{
			Extensions: perms,
		},
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		log.Errorf("Error in user SignCert for %s", cert.KeyId)
		return nil, nil, err
	}
	return cert.Marshal(), &end, nil
}

func main() {
	// logging setup
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	hook := sentryhook.New(nil)                  // will use raven.DefaultClient, or provide custom client
	hook.SetAsync(log.ErrorLevel)                // async (non-blocking) hook for errors
	hook.SetSync(log.PanicLevel, log.FatalLevel) // sync (blocking) for fatal stuff
	log.AddHook(hook)

	logrusEntry := log.NewEntry(log.StandardLogger())
	// Make sure that log statements internal to gRPC library are logged using the logrus Logger as well.
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	if len(os.Args) != 2 {
		log.Fatal("Please specify a config file for the server to use.")
	}

	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.WithField("fileName", os.Args[1]).Fatal(err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatal(err)
	}

	tc, err := credentials.NewServerTLSFromFile(conf.ServerCertPath, conf.ServerKeyPath)
	if err != nil {
		log.WithField("ServerCertPath", conf.ServerCertPath).WithField("ServerKeyPath", conf.ServerKeyPath).Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", conf.ListenPort))
	if err != nil {
		log.Fatal(err)
	}
	// Define customfunc to handle panic
	customFunc := func(ctx context.Context, p interface{}) (err error) {
		log.WithContext(ctx).Errorf("panic triggered: %v", p)
		return status.Errorf(codes.Unknown, "panic triggered: %v", p)
	}
	// Shared options for the logger, with a custom gRPC code to log level function.
	opts := []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandlerContext(customFunc),
	}
	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_logrus.StreamServerInterceptor(logrusEntry),
			grpc_recovery.StreamServerInterceptor(opts...), // panic interceptor must always be last
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
			grpc_recovery.UnaryServerInterceptor(opts...), // panic interceptor must always be last
		)),
		grpc.Creds(tc))

	sso := &SSOServer{
		Config: conf,
		Validator: &geecert.OIDCIDTokenValidator{
			ConfigurationURL: conf.OidcConfigurationUrl,
			ClientID:         conf.AllowedClientIdForIdToken,
			HostedDomain:     conf.AllowedDomainForIdToken,

			SkipEmailVerified:        conf.SkipEmailVerified,
			AudienceInAppID:          conf.LookForAudienceInAppId,
			GetHostedDomainFromEmail: conf.LookForHostedDomainInEmail,
		},
	}
	pb.RegisterGeeCertServerServer(grpcServer, sso)

	log.Info("Serving...")
	if conf.HttpListenPort != 0 {
		go sso.StartHTTP()
	}

	grpcServer.Serve(lis)
}
