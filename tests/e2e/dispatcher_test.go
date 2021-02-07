package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"path"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	hraftdispatcher "github.com/nodece/casbin-hraft-dispatcher"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func newEnforcer() (casbin.IDistributedEnforcer, error) {
	//a, err := gormadapter.NewAdapter("postgres", "postgresql://postgres:qplaFceC@127.0.01:5433/casbin", true)
	//if err != nil {
	//	return nil, err
	//}

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		return nil, err
	}

	e, err := casbin.NewDistributedEnforcer(m)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func newTLSConfig() (*tls.Config, error) {
	caRoot := path.Join("test_data", "ca")
	ca := path.Join(caRoot, "ca.pem")
	crt := path.Join(caRoot, "peer.pem")
	key := path.Join(caRoot, "peer-key.pem")

	caCertPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPEM)
	if !ok {
		return nil, errors.New("failed to parse root certificate")
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            roots,
		ClientCAs:          roots,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	}, nil
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("no local ip found")
}

func TestDispatcher(t *testing.T) {
	tlsConfig, err := newTLSConfig()
	assert.NoError(t, err)
	e, err := newEnforcer()
	assert.NoError(t, err)

	localIP, err := getLocalIP()
	assert.NoError(t, err)

	dispatcher, err := hraftdispatcher.NewHRaftDispatcher(&hraftdispatcher.DispatcherConfig{
		Enforcer:    e,
		TLSConfig:   tlsConfig,
		RaftAddress: fmt.Sprintf("%s:%d", localIP, 6790),
	})
	assert.NoError(t, err)

	e.SetDispatcher(dispatcher)
	go func() {
		err := dispatcher.Start()
		assert.NoError(t, err)
	}()
	<-time.After(10 * time.Second)

	_, err = e.AddPolicy("p", "role1", "res1", "read")
	assert.NoError(t, err)

	<-time.After(180 * time.Second)
	defer dispatcher.Stop()
}
