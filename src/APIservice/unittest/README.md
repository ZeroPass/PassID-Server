This is small test client script which calls PassID APIs: `passID.register`, `passID.login`, `passID.sayHello`
on to server with valid passport data (EF.SOD, EF.DG15 and passport signatures).

### Usage
Server should be configurated and ran with params `--dev` and `--dev-fc` with no tls `--no-tls` on port 80.
```
python apiserver.py --dev --dev-fc --no-tls -p 80 --mdb --mdb-pkd=<path_to_csca_dsc_folder>
```
