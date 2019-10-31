package main

import (
	"context"
	"net"
	"strings"

	"github.com/apex/log"
	"github.com/nmcclain/ldap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tierklinik-dobersberg/micro/pkg/auth/authn"
	"github.com/tierklinik-dobersberg/micro/pkg/config"
	"github.com/tierklinik-dobersberg/micro/pkg/service"
)

var (
	totalBindRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ldapd",
		Subsystem: "ldap",
		Name:      "bind_requests_total",
		Help:      "Total number of LDAP bind requests served",
	}, []string{"baseDN", "success"})
)

type ldapServer struct {
	addr            string
	baseDN          string
	nameAttrPrefix  string
	groupAttrPrefix string

	authn *authn.AuthN

	server *ldap.Server
}

func (l *ldapServer) Directive() service.Directive {
	return service.Directive{
		Name: "ldap",
		Init: func(s *service.Instance, c config.Dispenser) error {
			c.Next()

			for c.NextBlock() {
				switch strings.ToLower(c.Val()) {
				case "basedn", "dn":
					if !c.NextArg() {
						return c.ArgErr()
					}
					l.baseDN = c.Val()

				case "nameattr":
					if !c.NextArg() {
						return c.ArgErr()
					}
					l.nameAttrPrefix = c.Val()

				case "groupattr":
					if !c.NextArg() {
						return c.ArgErr()
					}
					l.groupAttrPrefix = c.Val()

				default:
					return c.SyntaxErr("unexpected keyword")
				}
			}

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

func (l *ldapServer) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	code, err := l.bind(bindDN, bindSimplePw, conn)

	if err == nil {
		var status string
		switch code {
		case ldap.LDAPResultSuccess:
			status = "success"
		case ldap.LDAPResultInvalidCredentials:
			status = "failed"
		default:
			status = "error"
		}

		totalBindRequests.WithLabelValues(l.baseDN, status).Inc()
	}

	return code, err
}

// Bind implements ldap.Binder
func (l *ldapServer) bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	username := bindDN
	groupname := ""

	// if we have a BaseDN make sure bindDN uses it
	// and extract the correct username out of it
	if l.baseDN != "" {
		if !strings.HasSuffix(bindDN, l.baseDN) {
			return ldap.LDAPResultInvalidCredentials, nil
		}

		parts := strings.Split(strings.TrimSuffix(bindDN, l.baseDN), ",")

		switch len(parts) {
		case 1: // only username
			username = strings.TrimPrefix(parts[0], l.nameAttrPrefix+"=")
		case 2:
			username = strings.TrimPrefix(parts[0], l.nameAttrPrefix+"=")
			groupname = strings.TrimPrefix(parts[1], l.groupAttrPrefix+"=")
		default:
			// TODO(ppacher): log error
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	accessToken, refreshToken, err := doLogin(context.Background(), l.authn.Host, username, bindSimplePw)
	if err == nil {
		// TODO(ppacher): immediately revoke the access and refresh tokens
		_, _ = accessToken, refreshToken

		if groupname != "" {
			// make sure the user that tries to authenticate is actually part of that group
		}

		return ldap.LDAPResultSuccess, nil
	}

	log.WithFields(log.Fields{
		"error":  err.Error(),
		"bindDN": bindDN,
	}).Warnf("failed to authenticate")

	return ldap.LDAPResultInvalidCredentials, nil
}

func (l *ldapServer) Close(boundDN string, conn net.Conn) error {
	log.WithField("bindDN", boundDN).Infof("connection closing")

	return nil
}
