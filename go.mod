module github.com/tierklinik-dobersberg/ldapd

go 1.13

require (
	github.com/apex/log v1.1.1
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/nmcclain/ldap v0.0.0-20191021200707-3b3b69a7e9e3
	github.com/ory/graceful v0.1.1
	github.com/prometheus/client_golang v1.2.1
	github.com/tierklinik-dobersberg/micro v0.0.0-20191031150513-7cd0957f16f6
	github.com/ugorji/go v1.1.7 // indirect
)

replace github.com/tierklinik-dobersberg/micro => ../micro

replace github.com/keratin/authn-go => ../../authn-go
