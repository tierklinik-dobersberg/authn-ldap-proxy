# authn-ldap-proxy

This repository contains a simple LDAP server that proxy Bind requests to [keratin/authn-server](https://keratin.tech) and [tierklinik-dobersberg/iam](https://github.com/tierklinik-dobersberg/iam). It's main purpose is to proxy LDAP simple bind authentication requests to authn-server and thus allow easy integration of third-party
applications. 

When configured only for [keratin/authn-server](https://keratin.tech) authentication requests are forwarded but group membership requests and filters will be ingored. For group management you'll also need to setup the IAM server from [tierklinik-dobersberg/iam](https://github.com/tierklinik-dobersberg/iam) that provides user and access management (authz) while using Keratin for authentication.

> **Warning**  
> `authn-ldap-proxy` proxies LDAP bind request to authn-server but does not do any session management. Using LDAP there is no way to tell a third-party application that a user account has been locked, deleted or that sessions have been invalidated! It's the responsibility of the third-party application to repeatingly ensure the user is still allowed to authenticate.  

`authn-ldap-proxy` is currently under heavy development and not yet ready to be used! If you still want to give it a try checkout the example configuration in `Configfile` and follow these instructions:

```bash
# Get the repository
git clone https://github.com/tierklinik-dobersberg/authn-ldap-proxy
cd ./authn-ldap-proxy

# Get dependencies and build authn-ldap-proxy
# A go1.13 build environment is required
go get ./...
go build .

# Start the LDAP server
./authn-ldap-proxy
```