package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/nmcclain/ldap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tierklinik-dobersberg/iam/pkg/client"
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

type token struct {
	access  string
	refresh string
	id      int
}

type ldapServer struct {
	addr            string
	baseDN          string
	nameAttrPrefix  string
	groupAttrPrefix string
	origin          string

	rw   sync.RWMutex
	conn map[net.Conn]*token

	authn *authn.AuthN
	iam   *iamConfig

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

				case "origin", "audience":
					if !c.NextArg() {
						return c.ArgErr()
					}
					l.origin = c.Val()

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

	l.conn = make(map[net.Conn]*token)

	l.server = ldap.NewServer()

	// EnforceLDAP tells the ldap library to do the heavy filtering stuff
	// so we don't need to handle all of that on our own (and still don't respond with
	// too much data)
	l.server.EnforceLDAP = true

	l.server.BindFunc("", l)
	l.server.CloseFunc("", l)
	l.server.SearchFunc("", l)

	// if there's no origin configured we'll use the hostname
	// of authn-server
	if l.origin == "" {
		l.origin = l.authn.Host
	}

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
	} else {
		log.Errorf(err.Error())
	}

	return code, err
}

func (l *ldapServer) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	log.Infof("request from %s for %s on %s in scope %s", bindDN, searchReq.Filter, searchReq.BaseDN, ldap.ScopeMap[searchReq.Scope])
	token, ok := l.getAccessToken(conn)
	if !ok {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("invalid sessions")
	}

	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}

	if filterEntity != "posixaccount" && filterEntity != "" {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	}

	cli, err := client.New(client.Config{
		Server: l.iam.Host,
		Token:  token.access,
	})
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	users, err := cli.ListUsers(context.Background())
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	var result ldap.ServerSearchResult
	result.ResultCode = ldap.LDAPResultSuccess

	/*
		filter, err := ldap.CompileFilter(searchReq.Filter)
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
	*/

	for _, u := range users {
		attrs := []*ldap.EntryAttribute{}
		add := func(name string, values ...string) {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   name,
				Values: values,
			})
		}

		add("cn", u.Username)
		add("uid", u.Username)
		add("givenName", u.Firstname)
		add("sn", u.Lastname)
		add("mail", u.MailAddress)
		add("phone", u.PhoneNumber)
		add("objectClass", "posixAccount")

		if u.Locked != nil {
			if *u.Locked {
				add("accountStatus", "inactive")
			} else {
				add("accountStatus", "active")
			}
		}

		dn := fmt.Sprintf("%s=%s,%s", l.nameAttrPrefix, u.Username, l.baseDN)
		entry := &ldap.Entry{
			DN:         dn,
			Attributes: attrs,
		}

		/*
			keep, code := ldap.ServerApplyFilter(filter, entry)
			if code != ldap.LDAPResultSuccess {
				return ldap.ServerSearchResult{ResultCode: code}, errors.New("ServerApplyFilter error")
			}

			if !keep {
				log.Infof("skipping request for %s", u.Username)
				continue
			}
		*/

		result.Entries = append(result.Entries, entry)
	}

	return result, nil
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

		parts := strings.Split(strings.TrimSuffix(bindDN, ","+l.baseDN), ",")

		switch len(parts) {
		case 1: // only username
			username = strings.TrimPrefix(parts[0], l.nameAttrPrefix+"=")
		case 2:
			username = strings.TrimPrefix(parts[0], l.nameAttrPrefix+"=")
			groupname = strings.TrimPrefix(parts[1], l.groupAttrPrefix+"=")
		default:
			// TODO(ppacher): log error
			return ldap.LDAPResultInvalidCredentials, fmt.Errorf("invalid bindDN: %s (%d)", bindDN, len(parts))
		}
	}

	accountID, accessToken, refreshToken, err := doLogin(context.Background(), l.authn.Host, l.origin, username, bindSimplePw)
	if err == nil {
		_, _ = accessToken, refreshToken
		id, err := strconv.Atoi(accountID)
		if err != nil {
			log.Errorf("invalid creds: %s", err.Error())
			return ldap.LDAPResultInvalidCredentials, err
		}

		if groupname != "" && l.iam.Host != "" {
			cli, err := client.New(client.Config{
				Server: l.iam.Host,
				Token:  accessToken,
			})
			if err != nil {
				return ldap.LDAPResultInvalidCredentials, err
			}

			log.Infof("loading groups ...")
			groups, err := cli.GetUserGroups(context.Background(), id)
			if err != nil {
				return ldap.LDAPResultInvalidCredentials, err
			}

			for _, g := range groups {
				log.Infof(g.Name)
				if g.Name == groupname {
					l.cacheAccessToken(conn, id, accessToken, refreshToken)
					return ldap.LDAPResultSuccess, nil
				}
			}

			return ldap.LDAPResultInvalidCredentials, nil
		}

		l.cacheAccessToken(conn, id, accessToken, refreshToken)
		return ldap.LDAPResultSuccess, nil
	}

	log.WithFields(log.Fields{
		"error":  err.Error(),
		"bindDN": bindDN,
	}).Warnf("failed to authenticate")

	return ldap.LDAPResultInvalidCredentials, err
}

func (l *ldapServer) Close(boundDN string, conn net.Conn) error {
	// TODO(ppacher): immediately revoke the access and refresh tokens
	log.WithField("bindDN", boundDN).Infof("connection closing")

	l.deleteToken(conn)

	return nil
}

func (l *ldapServer) cacheAccessToken(conn net.Conn, id int, access, refresh string) {
	l.rw.Lock()
	defer l.rw.Unlock()

	l.conn[conn] = &token{
		access:  access,
		refresh: refresh,
		id:      id,
	}
}

func (l *ldapServer) getAccessToken(conn net.Conn) (*token, bool) {
	l.rw.RLock()
	defer l.rw.RUnlock()

	t, ok := l.conn[conn]
	return t, ok
}

func (l *ldapServer) deleteToken(conn net.Conn) {
	l.rw.Lock()
	defer l.rw.Unlock()

	delete(l.conn, conn)
}
