# API service
API service which works on JSON-RPC protocol

### Prerequisites
* Python 3.7 or higher,
* Installed requirements from [here](../../../../../PassID-Server#prerequisites),
* Prepared PostgreSQL user and database (see [here](../../../../../PassID-Server#configure-postgresql-database)).

### Parameters

* --url (server URL address)
```
default: 127.0.0.1
type: strte
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --port (server port)
```
default: 8000
type: int
options: 
        -<PORT>      (<PORT>)
```

* --db-user (database username)
```
default: empty string
type: str
```

* --db-pwd (database password)
```
default: empty string
type: str
```

* --db-name (database name)
```
default: empty string
type: str
```



* --challenge-ttl (challente TTL)
```
default: 300e
type: int
```

* --cert (TLS certificate)
```
default: key in filepath "tls/passid_server.cer"
type: str
```

* -dev (developer mode)
```
default: false
type: bool
```

* -dev-fc (challenge is fixed)
```
default: false
type: bool
```

* -dev-no-tcv (skip eMRTD chain verification)
```
default: false
type: bool
```

* --key (database name)
```
default: key in filepath "tls/server_key.pem"
type: str
```

* --mdb (use MemoryDB instead of actualDB, test mode)
```
default: false
type: bool
```

* -no-tls (do not use TLS connection)
```
default: false
type: bool
```

##Call

Call from /src folder:
```
 sudo python3 src/APIservice/unittest/test_server.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0
```

Call from /src folder to run in background:
```
sudo nohup python3 src/APIservice/unittest/test_server.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0 &  
```

Action needs to be called as admin because of 80/443 port.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
