# API service
API service which works on JSON-RPC protocol

### Prerequisites
* Python 3.7 or higher,
* Installed dependencies from [here](../../../../../PassID-Server#prerequisites),
* Configured PostgreSQL database (see [here](../../../../../PassID-Server#configure-postgresql-database)).

### Usage
Run in the foreground:
```
 sudo python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0
```

Run in the background:
```
sudo nohup python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --dpwd <PWD> --db-name <NAME> --url 0.0.0.0 &  
```
*Note: Listening to port 443 requiers commands to be run as `sudo`.*


Local run using [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/c8e5095c6fde84a79ae0550c44e07dc68dfeac85/src/APIservice/proto/db.py#L256-L358):
```
python3 src/APIservice/apiserver/apiserver.py --mdb --mdb-pkd=<path_to_pkd_root>
```

Local run in dev mode using [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/c8e5095c6fde84a79ae0550c44e07dc68dfeac85/src/APIservice/proto/db.py#L256-L358):
```
python3 src/APIservice/apiserver/apiserver.py --dev --mdb --mdb-pkd=<path_to_pkd_root>
```

#### Server Parameters

* --url : server URL address)
```
default: 127.0.0.1
type: str
options:
        -localhost (127.0.0.1)
        -*         (0.0.0.0)
        -<IP>      (<IP>)
```

* --port : server port
```
default: 443 or 80 in case of `-no-tls` flag
type: int
options: 
        -<PORT>      (<PORT>)
```

* --db-user : database username
```
default: empty string
type: str
```

* --db-pwd : database password
```
default: empty string
type: str
```

* --db-name : database name
```
default: empty string
type: str
```



* --challenge-ttl : challente TTL
```
default: 300e
type: int
```

* --cert : server TLS certificate
```
default: key in filepath "tls/passid_server.cer"
type: str
```

* --dev : developer mode
```
default: false
type: bool
```

* --dev-fc : use fixed constant challenge with value of [this bytes](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/apiserver/apiserver.py#L26) instead of random challenge  
*To be used for testing server with [test client](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/unittest/test_client.py)*
```
default: false
type: bool
```

* --dev-no-tcv : skip verification of eMRTD trustchain (CSCA=>DSC=>SOD)
```
default: false
type: bool
```

* --key : server TLS private key
```
default: key in filepath "tls/server_key.pem"
type: str
```

* --log-level : set logging level. 0=verbose, 1=debug, 2=info, 3=warn, 4=error
```
default: 0 - verbose
type: int
```

* --mdb : use [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/c8e5095c6fde84a79ae0550c44e07dc68dfeac85/src/APIservice/proto/db.py#L256-L358) instead of sql database  
*Note: All entries are stored in memory (RAM) and are erased when server is restarted*
```
default: false
type: bool
```

* --mdb-pkd : path to the root folder of trustchain CSCA/DSC certificates to be loaded into [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/c8e5095c6fde84a79ae0550c44e07dc68dfeac85/src/APIservice/proto/db.py#L256-L358)
```
default: None
type: str
```

* --no-tls : do not use TLS connection
```
default: false
type: bool
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
