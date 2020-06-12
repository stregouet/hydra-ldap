# Hydra-ldap

Hydra-ldap is an Identity Provider for [Ory Hydra](https://ory.sh/hydra) over LDAP.

It starts as a fork from [Werther](https://github.com/i-core/werther), then I rewrite it for different reasons:

1. a use case to start learning golang ;)
2. change library stack to ease adding new features:
  - testify to ease mock and assert in unit test
  - go-macaron to ease http routes/middlewares management (especially with
    i18n)
  - viper to ease configuration with either file (like yaml) or
    environment variables
  - zerolog to ease sending log to journald with syslog level at start
3. add some features:
  - optional reset password form (via email)
  - manage user authorization for each oauth2 application (relying party)
    either from ldap or from a config file (if already existing LDAP tree
    structure is not well defined for such use case)


## Configuration

Hydra-ldap uses [viper](https://github.com/spf13/viper) under the hood, so you
can configure it either with yaml, toml, json file or environment variables.

[config.yml](config.sample.yml) is an example of configuration with some explanations.


## User authorization

User is authorized to access a particular oauth2 client (relying party) if:

1. an ldap entry exists according to `userFilter` (cf. `internal/ldap/ldap.go`)
2. a bind operation with password and user associated DN return no error
3. this user is a member of any group inside `groupbasedn` concatenated with
   `ou=CLIENT-ID` where `CLIENT-ID` should be the client id as defined in your
   hydra server.

So for example with the following LDAP tree:

```
dc=example,dc=com
|-- ou=users
    |-- uid=jdupont
    |-- uid=babar
|-- ou=apps
  |-- ou=clientid
    |-- cn=basicuser
        member: uid=jdupont,ou=users,dc=example,dc=com
```

user `jdupont` is allowed to access relying party with hydra id `clientid` but
not user `babar`



## License

The code in this project is licensed under [MIT license][LICENSE].
