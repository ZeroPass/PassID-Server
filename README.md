# PassID ICAO data
Parse and store the data from ICAO source [ICAO download](https://pkddownloadsg.icao.int/download).

## Getting Started
The repository contains data structures and algorithms to parse/validate/store ICAO data.

### Prerequisites
* [Python 3.7 or higher](https://www.python.org/downloads/)

Check this [webiste](https://wiki.python.org/moin/BeginnersGuide/Download) for installation tutorial.

* [asn1crypto](https://github.com/wbond/asn1crypto)
```
pip3 install asn1crypto
```

* [cryptography](https://github.com/pyca/cryptography)     (*Note: Library has to be patched see [README](https://github.com/ZeroPass/PassID-Server/blob/master/src/pymrtd/pki/README.md) of pki module*)
```
pip3 install cryptography
```

* [Python LDIF parser](https://ldif3.readthedocs.io/en/latest/)
```
pip3 install ldif3
```

* [Paramiko](https://pypi.org/project/paramiko/)
```
pip3 install paramiko
```

* [SQLAlchemy](https://www.sqlalchemy.org/)
```
pip3 install sqlalchemy
```

* [JSON-RPC](https://github.com/pavlov99/json-rpc)
```
pip3 install json-rpc
```

* [werkzeug](https://palletsprojects.com/p/werkzeug/)
```
pip3 install werkzeug
```

* [ColoredLogs](https://coloredlogs.readthedocs.io/en/latest/)
```
pip3 install coloredlogs
```

* [pycountry](https://github.com/flyingcircusio/pycountry)
```
pip install pycountry
```

* [PostgreSQL adapter - psycopg2](http://initd.org/psycopg/)
```
pip3 install psycopg2
```

### Configure PostgreSQL database


* Creating user

```$ sudo -u postgres createuser <username>```

* Creating Database

```$ sudo -u postgres createdb <dbname>```

* Giving the user a password

```$ sudo -u postgres psql```

```psql=# alter user <username> with encrypted password '<password>';```

* Granting privileges on database

```psql=# grant all privileges on database <dbname> to <username> ;```


### Structure definition
* [Python Machine Readable Trevlers Document](src/pymrtd)

### Separated project documentation
* API service [README](src/APIservice#api-service)
* Web app [README](src/WebApp#webapp-data)

### Other documentation
* [ICAO LDAP-LDIF structure specification](https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
