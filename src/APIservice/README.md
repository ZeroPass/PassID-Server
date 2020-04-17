# API service
PassID API service serves endpoint on JSON-RPC protocol.  
Server has 6 API methods defined.
All API mehods are defined in [api.py](https://github.com/ZeroPass/PassID-Server/blob/18e134e9316bf3888ae5e51ce4cf46468e832f44/src/APIservice/api.py#L56-L172) and their logic is defined in class [PassIdProto](https://github.com/ZeroPass/PassID-Server/blob/66b2ea724ec9a515d07298eed828c6849ec1cbbc/src/APIservice/proto/proto.py#L65-L438).  
 To demonstrate the eMRTD PoC, API methods `passID.register` and `passID.login` should be called respectively.

## Table of Contents  
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  + [Server Parameters](#server-parameters)
- [API Methods](#api-methods)
- [API Errors](#api-errors)
- [Testing](#testing)
- [License](#license)

## Prerequisites
* Python 3.7 or higher,
* Installed dependencies from [here](../../../../../PassID-Server#prerequisites),
* Configured PostgreSQL database (see [here](../../../../../PassID-Server#configure-postgresql-database)).

## Usage
Run in the foreground:
```
 sudo python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url 0.0.0.0
```

Run in the background:
```
sudo nohup python3 src/APIservice/apiserver/apiserver.py --db-user <USER> --db-pwd <PWD> --db-name <NAME> --url 0.0.0.0 &  
```
*Note: Listening to port 443 requiers commands to be run as `sudo`.*


Local run using [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/ddcc6073d298cb1a4e0d99195d928a9dce0f78e5/src/APIservice/proto/db.py#L262-L375):
```
python3 src/APIservice/apiserver/apiserver.py --mdb --mdb-pkd=<path_to_pkd_root>
```

Local run in dev mode using [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/ddcc6073d298cb1a4e0d99195d928a9dce0f78e5/src/APIservice/proto/db.py#L262-L375):
```
python3 src/APIservice/apiserver/apiserver.py --dev --mdb --mdb-pkd=<path_to_pkd_root>
```

### Server Parameters

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



* --challenge-ttl : number of seconds before requested challenge expires
```
default: 300
type: int
```

* --cert : server TLS certificate
```
default: key in filepath "tls/passid_server.cer"
type: str
```

* --dev : developer mode. When this flag is set all newly registered accounts will expired after 1 minute.  
See also other *--dev-** flags.
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

* --mdb : use [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/ddcc6073d298cb1a4e0d99195d928a9dce0f78e5/src/APIservice/proto/db.py#L262-L375) instead of sql database  
*Note: All entries are stored in memory (RAM) and are erased when server is restarted*
```
default: false
type: bool
```

* --mdb-pkd : path to the root folder of trustchain CSCA/DSC certificates to be loaded into [MemoryDB](https://github.com/ZeroPass/PassID-Server/blob/ddcc6073d298cb1a4e0d99195d928a9dce0f78e5/src/APIservice/proto/db.py#L262-L375)
```
default: None
type: str
```

* --no-tls : do not use TLS connection
```
default: false
type: bool
```
## API Methods
* **passID.ping**  
  Used for testing connection with server.  
  **params:** `int32` [*ping*] number  
  **returns:** `int32` random [*pong*] number  
  
* **passID.getChallenge**  
  Returns new random 32 bytes chanllenge to be at register or login to establish new session with.  
  **params:** none  
  **returns:** 32-byte [*challenge*]  
  
* **passID.cancelChallenge**  
  Cancel requested challenge.  
  **params:** `base64` encoded 32-byte [*challenge*]  
  **returns:** none  
  
* **passID.register**  
  Register new user using eMRTD credentials. Account will be valid for 10 minutes (1 minute if `--dev` flag was used) after which it will expire and user will have to register again.  
  By default EF.SOD is always validated into eMRTD trustchain unless `--dev-no-tcv` flag was used.  
  **params:**
    * `base64` encoded [[*dg15*]](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/dg.py#L189-L203) file (eMRTD AA Public Key)
    * `base64` encoded [[*SOD*]](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/sod.py#L135-L195) file (eMRTD Data Security Object)
    * `hex` encoded 4-byte [[*cid*]](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/proto/challenge.py#L12-L37) (challenge id)
    * ordered list [*csigs*] of 4 `base64` encoded eMRTD signatures (AA) made over 8-byte long challenge chunks ([see verification process](https://github.com/ZeroPass/PassID-Server/blob/5800f368b03de6bf8d2ee9d26ba974ff3284b215/src/APIservice/proto/proto.py#L244-L249))
    * (Optional)`base64` encoded [[*dg14*]](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/dg.py#L161-L185) file.  
    File is required if elliptic curve cryptography was used to produce signatures. (EF.DG14 contains info about ECC signature algorithm)

  **returns:**
    * `base64` encoded 20-byte [*uid*] [user id](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/APIservice/proto/user.py#L10-L39)
    * `base64` encoded 32-byte HMAC [[*session_key*]](https://github.com/ZeroPass/PassID-Server/blob/23af931ab1ef8fdc0c2d948c1fd4a14a71d7beba/src/APIservice/proto/session.py#L12-L43)
    * `int32` unix time when session [*expires*] (not used).
    
 * **passID.login**  
  Logins existing user using eMRTD credentials.  
  **params:**
    * `base64` encoded 20-byte [*uid*] [user id](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/APIservice/proto/user.py#L10-L39)
    * `hex` encoded 4-byte [[*cid*]](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/proto/challenge.py#L12-L37) (challenge id)
    * ordered list [*csigs*] of 4 `base64` encoded eMRTD signatures (AA) made over 8-byte long challenge chunks ([see verification process](https://github.com/ZeroPass/PassID-Server/blob/5800f368b03de6bf8d2ee9d26ba974ff3284b215/src/APIservice/proto/proto.py#L244-L249))
    * (Optional) `base64` encoded [[*dg1*]](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/pymrtd/ef/dg.py#L148-L158) file (eMRTD MRZ).  
    By default EF.DG1 is required [second](https://github.com/ZeroPass/PassID-Server/blob/66b2ea724ec9a515d07298eed828c6849ec1cbbc/src/APIservice/proto/proto.py#L155-L159) time user logs-in.
    
   **returns:**
    * `base64` encoded 32-byte HMAC [[*session_key*]](https://github.com/ZeroPass/PassID-Server/blob/23af931ab1ef8fdc0c2d948c1fd4a14a71d7beba/src/APIservice/proto/session.py#L12-L43)
    * `int32` unix time when session [*expires*] (not used).
    
* **passID.sayHello**  
  Returns grettings from server. Returned greeting is in format: *"Hi, anonymous!"* or  
  *"Hi, <LAST_NAME> <FIRST_NAME>!"* if EF.DG1 was provided at login.  
  (API method is defined only to present validated and parsed personal user data back to client)  
  **params:**
    * `base64` encoded 20-byte [*uid*] [user id](https://github.com/ZeroPass/PassID-Server/blob/a87cb5cc55c160a9ca80583ecb6099d7a6e57660/src/APIservice/proto/user.py#L10-L39)
    *  `base64` encoded 32-byte [*mac*] digest of [HMAC-SHA256](https://github.com/ZeroPass/PassID-Server/blob/66b2ea724ec9a515d07298eed828c6849ec1cbbc/src/APIservice/proto/session.py#L63-L69) calculated over [[api name | uid]](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/proto/proto.py#L206) using session key (generated at register/login).
    
   **returns:**
    * `str` greeting
    
## API Errors
Server can return these PassID errors defined [here](https://github.com/ZeroPass/PassID-Server/blob/master/src/APIservice/proto/proto.py#L21-L62).

## Testing
See [test client](unittest) in unittest folder.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
