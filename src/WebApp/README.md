# WebApp data
Portal where anyone can upload and parse ICAO data.

### Prerequisites
* Python 3.7 or higher,
* Installed requirements from [here](../README.md),
* Prepared PostgreSQL user and database (see [here](../README.md])).

### Parameters

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

##Call
Call from /src folder:
```
 python3 WebApp/server.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url localhost
```

Call from /src folder to run in background:
```
nohup python3 WebApp/server.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url localhost &  
```
## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
