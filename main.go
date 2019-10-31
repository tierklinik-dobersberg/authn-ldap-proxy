package main

import (
	"log"
	"sync"

	"github.com/ory/graceful"
	"github.com/tierklinik-dobersberg/micro/pkg/auth/authn"
	"github.com/tierklinik-dobersberg/micro/pkg/config"
	"github.com/tierklinik-dobersberg/micro/pkg/metrics"
	"github.com/tierklinik-dobersberg/micro/pkg/server"
	"github.com/tierklinik-dobersberg/micro/pkg/service"
)

func main() {
	ldap := ldapServer{
		authn: authn.New(),
		iam:   &iamConfig{},
	}

	instance := service.NewInstance(service.Config{
		Name:        "ldapd",
		InputLoader: config.FileLoader("Configfile"),
		Directives: []service.Directive{
			metrics.Directive,
			server.Directive(),
			ldap.Directive(),
			ldap.authn.Directive(),
			ldap.iam.Directive(),
		},
	})

	if err := ldap.Setup(); err != nil {
		log.Fatal(err)
	}

	// we use the HTTP router to serve the /metrics endpoint
	if err := instance.InitRouter(); err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	if server.DefaultServer.Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := server.Serve(instance); err != nil {
				log.Fatal(err)
			}
		}()
	}

	// Actually start serving LDAP connections
	if err := graceful.Graceful(ldap.Serve, ldap.Shutdown); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}
