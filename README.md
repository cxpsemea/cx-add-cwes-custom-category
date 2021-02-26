# Checkmarx Add CWE Custom Category - Python Script
This is a Python script used for adding to Checkmarx Server a custom category based on CWEs of Checkmarx Queries

# Checkmarx Versions Supported:
Checkmarx versions supported are:
- 9.3
- 9.2
- 9.0
- 8.9
- 8.8

# Python Versions Supported:
Python versions supported are:
- 3.6
- 3.7
- 3.8
- 3.9

#Install Dependencies:

All dependencies needed can be found in the file ``requirements.txt``.

Dependencies:
- zeep - SOAP Client
- requests - REST API Client
- pyodbc - Database Client

To install the dependencies please run the following command:

```batch
python -m pip install -r requirements.txt
```

# Arguments
This script can take the following arguments/flags:

| Flag (short,long, ENV.VAR) | Arg. Value (Example) | Description | Type | Is Required* | Default |
| ------------- | ------------- | ------------- |------------- | ------------- | ------------- |
| -h,--help | (n/a) | Access Help Manual | Boolean | No | |
| -v,--version | (n/a) | Version | Boolean | No | |
| -cxs,--cxserver,CX_SERVER | http://localhost | Checkmarx Server URL | String | Yes* | |
| -cxu,--cxuser,CX_USER | miguel | Checkmarx Username| String | Yes* | |
| -cxp,--cxpassword,CX_PASSWORD | ****** | Checkmarx Password | Secure String | Yes* | |
| -dbs,--dbserver,DB_SERVER | localhost\CHECKMARX | Database Server URL | String | Yes* | |
| -dbu,--dbuser,DB_USER | miguel | Database Username | String | Yes* | |
| -dbp,--dbpassword,DB_PASSWORD | ****** | Database Password | Secure String | Yes* | |
| -dbd,--dbdriver,DB_DRIVER | SQL Server | MSSQL DB Driver| String | No | ODBC Driver 17 for SQL Server |
| -cn,--categoryname,CATEGORY_NAME | CWEs | Category Name | String | No | CWEs |
| -cgp,--categorygroupprefix,CATEGORY_GROUP_PREFIX | CWE  | Category Group Prefix | String | No | CWE  |
| -ucn,--unknowncwename,UNKNOWN_CWE_NAME | No CWE  | Unknown CWE Name | String | No | Unknown  |
| -d,--debug,DEBUG | True | Debug Mode | Boolean | No | False |
| -tc,--trustcerts,TRUST_CERTS | True | Trust SSL Certificates | Boolean | No | False |


# Execution

```batch
usage: CWE Custom Category Script [-h] [-v] [-cxu CXUSER] [-cxp CXPASSWORD] [-cxs CXSERVER] [-dbu DBUSER] [-dbp DBPASSWORD] [-dbs DBSERVER] [-dbd DBDRIVER] [-cn CATEGORYNAME] [-cgp CATEGORYGROUPPREFIX] [-ucn UNKNOWNCWENAME] [-d]
                                  [-tc]

CWE Custom Category Script

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Version
  -cxu CXUSER, --cxuser CXUSER
                        Checkmarx Username
  -cxp CXPASSWORD, --cxpassword CXPASSWORD
                        Checkmarx Password
  -cxs CXSERVER, --cxserver CXSERVER
                        Checkmarx Server URL
  -dbu DBUSER, --dbuser DBUSER
                        Database Username
  -dbp DBPASSWORD, --dbpassword DBPASSWORD
                        Database Password
  -dbs DBSERVER, --dbserver DBSERVER
                        Database Server URL
  -dbd DBDRIVER, --dbdriver DBDRIVER
                        Checkmarx MSSQL DB Driver
  -cn CATEGORYNAME, --categoryname CATEGORYNAME
                        Category Name
  -cgp CATEGORYGROUPPREFIX, --categorygroupprefix CATEGORYGROUPPREFIX
                        Category Group Prefix
  -ucn UNKNOWNCWENAME, --unknowncwename UNKNOWNCWENAME
                        Unknown CWE Name
  -d, --debug           Enable Debug
  -tc, --trustcerts     Trust Certificates

```

Get Version:
```batch
python cwe-custom-category.py -v
python cwe-custom-category.py --version
```

Get Help:
```batch
python cwe-custom-category.py -h
python cwe-custom-category.py --help
```

Run + Arguments:
```batch
python cwe-custom-category.py -cxs http://checkmarx.company.com -cxu username@cx -cxp ******** -dbs localhos\CHECKMARX -dbu username@cx -dbp ********
```

Run + Arguments + Trust SSL Certificates:
```batch
python cwe-custom-category.py -cxs http://checkmarx.company.com -cxu username@cx -cxp ******** -dbs localhos\CHECKMARX -dbu username@cx -dbp ******** -tc
```

Run + Arguments + Debug:
```batch
python cwe-custom-category.py -cxs http://checkmarx.company.com -cxu username@cx -cxp ******** -dbs localhos\CHECKMARX -dbu username@cx -dbp ******** -d
```

Run + Arguments + Trust SSL Certificates + Debug:
```batch
python cwe-custom-category.py -cxs http://checkmarx.company.com -cxu username@cx -cxp ******** -dbs localhos\CHECKMARX -dbu username@cx -dbp ******** -tc -d
```

Run + Environment Variables:
```batch
set CX_SERVER=http://checkmarx.company.com
set CX_USER=username@cx
set CX_PASSWORD=********
set DB_SERVER=localhos\CHECKMARX
set DB_USER=username@cx
set DB_PASSWORD=********
```
```batch
python cwe-custom-category.py
```

Run + Environment Variables + Trust SSL Certificates:
```batch
set CX_SERVER=http://checkmarx.company.com
set CX_USER=username@cx
set CX_PASSWORD=********
set DB_SERVER=localhos\CHECKMARX
set DB_USER=username@cx
set DB_PASSWORD=********
set TRUST_CERTS=True
```
```batch
python cwe-custom-category.py
```

Run + Environment Variables + Debug:
```batch
set CX_SERVER=http://checkmarx.company.com
set CX_USER=username@cx
set CX_PASSWORD=********
set DB_SERVER=localhos\CHECKMARX
set DB_USER=username@cx
set DB_PASSWORD=********
set DEBUG=True
```
```batch
python cwe-custom-category.py
```

Run + Environment Variables + Trust SSL Certificates + Debug:
```batch
set CX_SERVER=http://checkmarx.company.com
set CX_USER=username@cx
set CX_PASSWORD=********
set DB_SERVER=localhos\CHECKMARX
set DB_USER=username@cx
set DB_PASSWORD=********
set TRUST_CERTS=True
set DEBUG=True
```
```batch
python cwe-custom-category.py
```

# License
MIT License

Copyright (c) 2021 Miguel Freitas
