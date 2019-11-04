package main

import (
	"github.com/tierklinik-dobersberg/micro/pkg/config"
	"github.com/tierklinik-dobersberg/micro/pkg/service"
)

type iamConfig struct {
	Host string
}

func (iam *iamConfig) Directive() service.Directive {
	return service.Directive{
		Name: "iam",
		Init: func(s *service.Instance, c config.Dispenser) error {
			c.Next()

			if !c.NextArg() {
				return c.ArgErr()
			}
			iam.Host = c.Val()

			return nil
		},
	}
}
