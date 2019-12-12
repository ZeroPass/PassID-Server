# API service
API service which works on JSON-RPC protocol

### Prerequisites
* Python 3.7 or higher,
* Installed requirements from [here](../../../../../PassID-Server#prerequisites),
* Prepared PostgreSQL user and database (see [here](../../../../../PassID-Server#configure-postgresql-database)).

### Usage

Call from /src folder:
```
 sudo python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0
```

Call from /src folder to run in background:
```
sudo nohup python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0 &  
```

Call from /src folder to run in background using MemoryDB:
```
sudo nohup python3 src/APIservice/apiserver/apiserver.py -mdb -mdb-pkd=<path_to_pkd_root> --url 0.0.0.0 &  
```

*Note: Listening to port 443 requiers commands to be run as `sudo`.*

#### Server Parameters

* --url (server URL address)
```
default: 127.0.0.1
type: str
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --port (server port)
```
default: 443 or 80 in case of `-no-tls` flag
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

* --cert (server TLS certificate)
```
default: key in filepath "tls/passid_server.cer"
type: str
```

* -dev (developer mode)
```
default: false
type: bool
```

* -dev-fc (challenge is fixed to [this bytes](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/apiserver/apiserver.py#L26))
```
default: false
type: bool
```

* -dev-no-tcv (skip eMRTD chain verification)
```
default: false
type: bool
```

* --key (server TLS private key)
```
default: key in filepath "tls/server_key.pem"
type: str
```

* -log-level (set logging level)
```
default: 0 - verbose
type: int
```

* --mdb (use MemoryDB instead of actual DB. *Note: MemoryDB is reset every time server is restarted.*)
```
default: false
type: bool
```

* -mdb-pkd (path to the root folder of trustchain PKD CSCA/DSC certificates to be loaded into MemoryDB)
```
default: None
type: str
```

* -no-tls (do not use TLS connection)
```
default: false
type: bool
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
