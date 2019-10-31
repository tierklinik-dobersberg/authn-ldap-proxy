package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/apex/log"
	"github.com/nmcclain/ldap"
	"github.com/tierklinik-dobersberg/micro/pkg/auth/authn"
	"github.com/tierklinik-dobersberg/micro/pkg/config"
	"github.com/tierklinik-dobersberg/micro/pkg/service"
)

type ldapServer struct {
	addr  string
	authn *authn.AuthN

	server *ldap.Server
}

func (l *ldapServer) Directive() service.Directive {
	return service.Directive{
		Name: "ldap",
		Init: func(s *service.Instance, c config.Dispenser) error {

			return nil
		},
	}
}

func (l *ldapServer) Setup() error {
	if l.addr == "" {
		l.addr = ":3893"
	}

	l.server = ldap.NewServer()
	l.server.BindFunc("", l)
	l.server.CloseFunc("", l)

	return nil
}

func (l *ldapServer) Serve() error {
	return l.server.ListenAndServe(l.addr)
}

func (l *ldapServer) Shutdown(ctx context.Context) error {
	select {
	case l.server.Quit <- true:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Bind implements ldap.Binder
func (l *ldapServer) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	form := url.Values{}
	form.Add("username", bindDN)
	form.Add("password", bindSimplePw)

	req, err := http.NewRequest("POST", l.authn.Host+"/session", strings.NewReader(form.Encode()))
	if err != nil {
		log.Errorf(err.Error())
		return ldap.LDAPResultOperationsError, nil
	}

	req.Header.Add("Origin", "ldap://app.example.com")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf(err.Error())
		return ldap.LDAPResultOperationsError, nil
	}

	if res.StatusCode == 201 {
		return ldap.LDAPResultSuccess, nil
	}
	log.Errorf(res.Status)

	return ldap.LDAPResultInvalidCredentials, nil
}

func (l *ldapServer) Close(boundDN string, conn net.Conn) error {
	log.WithField("bindDN", boundDN).Infof("connection closing")

	return nil
}
