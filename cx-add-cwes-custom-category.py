import argparse
import logging
import logging.config
import os
import sys
import warnings
from json.decoder import JSONDecodeError

import pyodbc
import requests
from requests import Session
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from zeep import Client
from zeep import Settings
from zeep.transports import Transport

warnings.simplefilter('ignore', InsecureRequestWarning)
# DB Queries #
q_insert_category = "INSERT INTO dbo.CategoriesTypes (Id, Typename) VALUES ((SELECT (MAX(Id)+1) FROM dbo.CategoriesTypes), ?)"
q_identity_insert_category_types_on = "SET IDENTITY_INSERT dbo.CategoriesTypes ON"
q_identity_insert_category_types_off = "SET IDENTITY_INSERT dbo.CategoriesTypes OFF"
q_check_category = "SELECT Id,Typename FROM dbo.CategoriesTypes WHERE TypeName=?"
q_clean_category_for_query_1 = "DELETE FROM CategoryForQuery WHERE CategoryId IN (SELECT Id FROM dbo.Categories WHERE CategoryType=?)"
q_clean_category_for_query_2 = "DELETE FROM CategoryForQuery WHERE CategoryId=?"
q_clean_categories = "DELETE FROM dbo.Categories WHERE CategoryType=?"
q_check_categories = "SELECT * FROM dbo.Categories WHERE CategoryType=?"
q_identity_insert_categories_on = "SET IDENTITY_INSERT dbo.Categories ON"
q_identity_insert_categories_off = "SET IDENTITY_INSERT dbo.Categories OFF"
q_insert_category_description = "INSERT INTO dbo.Categories (Id, CategoryName,CategoryType) values ((SELECT (MAX(Id)+1) FROM dbo.Categories),?,?)"
q_check_categories_description = "SELECT * FROM dbo.Categories WHERE CategoryType=? and CategoryName=?"
q_check_query = "SELECT * FROM dbo.Query WHERE QueryId=?"
q_insert_category_query = "INSERT INTO CategoryForQuery (QueryId,CategoryId) VALUES (?,?)"

DATABASE = "CxDB"
HTTP = "http://"
HTTPS = "https://"
MASKED_PASSWORD = "***********"
DEFAULT_TIMEOUT = 5  # seconds
DB_TIMEOUT = 5  # seconds
SEPARATOR = "---------------------------"


def get_env(key, default_value, is_boolean):
    if key:
        try:
            value = os.environ[key]
            if is_boolean:
                if len(value) == 0:
                    return False
                else:
                    return value.lower() == "True".lower()
            else:
                return value
        except KeyError:
            logging.debug(f'Cannot retrieve {key} key. Returning default value: {default_value}')
            return default_value
        except TypeError:
            logging.debug(f'Cannot retrieve {key} key. Returning default value: {default_value}')
            return default_value
    else:
        return default_value


DEFAULT_VERSION = "1.1.0"
DEFAULT_NAME = "Checkmarx Add CWE Custom Category - Python Script"
DEFAULT_CX_SERVER = ""
DEFAULT_CX_USERNAME = ""
DEFAULT_CX_PASSWORD = ""
DEFAULT_DB_SERVER = ""
DEFAULT_DB_USERNAME = ""
DEFAULT_DB_PASSWORD = ""
DEFAULT_DB_DRIVER = "SQL Server"
DEFAULT_DEBUG_ENABLED = False
DEFAULT_TRUST_CERTS_ENABLED = False
DEFAULT_CATEGORY_NAME = "CWEs"
DEFAULT_CATEGORY_GROUP_PREFIX = "CWE "
DEFAULT_UNKNOWN_CWE_NAME = "Unknown"

__app__ = get_env('APP_NAME', DEFAULT_NAME, False)
__version__ = get_env('VERSION', DEFAULT_VERSION, False)
__cx_server__ = get_env('CX_SERVER', DEFAULT_CX_SERVER, False)
__cx_username__ = get_env('CX_USER', DEFAULT_CX_USERNAME, False)
__cx_password__ = get_env('CX_PASSWORD', DEFAULT_CX_PASSWORD, False)
__db_server__ = get_env('DB_SERVER', DEFAULT_DB_SERVER, False)
__db_username__ = get_env('DB_USER', DEFAULT_DB_USERNAME, False)
__db_password__ = get_env('DB_PASSWORD', DEFAULT_DB_PASSWORD, False)
__db_driver__ = get_env('DB_DRIVER', DEFAULT_DB_DRIVER, False)
__category_name__ = get_env('CATEGORY_NAME', DEFAULT_CATEGORY_NAME, False)
__category_group_prefix__ = get_env('CATEGORY_GROUP_PREFIX', DEFAULT_CATEGORY_GROUP_PREFIX, False)
__unknown_cwe_name__ = get_env('UNKNOWN_CWE_NAME', DEFAULT_UNKNOWN_CWE_NAME, False)
_debug_ = get_env('DEBUG', DEFAULT_DEBUG_ENABLED, True)
__trustcerts__ = get_env('TRUST_CERTS', DEFAULT_TRUST_CERTS_ENABLED, True)


def is_str(string):
    return string is not None and isinstance(string, str) and len(string) > 0


def is_valid_url(url):
    return is_str(url) and (url.startswith(HTTP) or url.startswith(HTTPS))


def cx_login(cx_server, service, cx_user, cx_password):
    logging.info(f'Trying to login to {cx_server} with Username {cx_user}...')
    login_response = service.Login({"User": cx_user, "Pass": cx_password}, 1033)
    logging.debug(login_response)
    if login_response.IsSuccesfull:
        logging.info(f'Login Success to {cx_server}')
        return login_response.SessionId
    else:
        raise Exception(f'Login Failed to {cx_server}: {login_response.ErrorMessage}')


def get_queries(service, session, cx_version):
    logging.info(f'Retrieving Query Groups...')
    if cx_version.startswith("8."):
        query_collection_response = service.GetQueryCollection(session)
    else:
        query_collection_response = service.GetQueryCollection('')
    logging.debug(query_collection_response)
    if query_collection_response.IsSuccesfull:
        query_groups = query_collection_response.QueryGroups.CxWSQueryGroup
        logging.info(f'Get Queries Success: {len(query_groups)} Query Groups retrieved')
        return query_groups
    else:
        raise Exception(f'Get Queries failed: {query_collection_response.ErrorMessage}')


def get_queries_categories_object(query_groups, category_name, category_group_prefix, unknown_cwe_name):
    logging.info("Generating Category Object...")
    cwes = []
    for query_group in query_groups:
        for query in query_group["Queries"]["CxWSQuery"]:
            if query["Cwe"] == 0:
                # Some Queries have no CWE assigned
                cwe_name = unknown_cwe_name
            else:
                cwe_name = category_group_prefix + str(query["Cwe"])
            add = True
            for cwe in cwes:
                if cwe["name"] == cwe_name:
                    cwe["queryIds"].append(query["QueryId"])
                    add = False
                    break
            if add:
                json = {
                    "name": cwe_name,
                    "queryIds": [query["QueryId"]]
                }
                cwes.append(json)
    logging.info(f'Found {len(cwes)} different CWEs')
    return {
        "category": {
            "name": category_name,
            "groups": cwes
        }
    }


# Check if Category exists
def check_category(conn, category_name):
    logging.info(f'Checking if Category "{category_name}" exists on Database...')
    cursor = conn.cursor()
    cursor.execute(q_check_category, category_name)
    rows = cursor.fetchall()
    if len(rows) > 0:
        logging.info(f'Category "{category_name}" already exists')
        category_type_id = rows[0][0]
        return str(category_type_id)
    else:
        logging.info(f'Category "{category_name}" does not exist on Database')
        logging.info(f'Adding Category "{category_name}" to Database...')

        cursor.execute(q_identity_insert_category_types_on)
        conn.commit()
        cursor.execute(q_insert_category, category_name)
        conn.commit()
        cursor.execute(q_identity_insert_category_types_off)
        conn.commit()
        logging.info(f'Category "{category_name}" was added to Database with Success !')

        logging.info(f'Checking if Category "{category_name}" exists on Database...')
        cursor.execute(q_check_category, category_name)
        rows = cursor.fetchall()
        if len(rows) > 0:
            logging.info(f'Category "{category_name}" already exists')
            category_type_id = rows[0][0]
            return str(category_type_id)
        else:
            raise Exception(f'Category "{category_name}" does not exist on Database')


##########################################################################
# Clean old matched data, first remove data from CategoryForQuery #
# and then remove from Categories Table                           #
##########################################################################
def clean_category_data(conn, category_id, category_name):
    logging.info(f'Cleaning data for Category "{category_name}" with ID "{category_id}" on Database...')
    cursor = conn.cursor()
    cursor.execute(q_clean_category_for_query_1, category_id)
    conn.commit()

    cursor.execute(q_clean_category_for_query_2, category_id)
    conn.commit()

    cursor.execute(q_clean_categories, category_id)
    conn.commit()

    cursor.execute(q_check_categories, category_id)
    rows = cursor.fetchall()
    if len(rows) > 0:
        logging.error(f'Data for Category "{category_name}" with ID "{category_id}" failed to get cleared !')
    else:
        logging.info(
            f'Data for Category "{category_name}" with ID "{category_id}" was cleared from Database with success!')


# Insert new category data
def insert_category_data(conn, category_name, category_type_id, category_object):
    logging.info(f'Inserting new data for Category "{category_name}" with ID "{category_type_id}" on Database...')
    cursor = conn.cursor()
    non_existing_queries = []
    for group in category_object["category"]["groups"]:
        group_name = group["name"]

        cursor.execute(q_identity_insert_categories_on)
        conn.commit()
        cursor.execute(q_insert_category_description, (group_name, category_type_id))
        conn.commit()
        cursor.execute(q_identity_insert_categories_off)
        conn.commit()
        cursor.execute(q_check_categories_description, (category_type_id, group_name))
        rows = cursor.fetchall()
        category_id = rows[0][0]
        for query_id in group["queryIds"]:
            cursor.execute(q_check_query, str(query_id))
            rs = cursor.fetchall()
            if len(rs) == 1:
                cursor.execute(q_insert_category_query, (str(query_id), str(category_id)))
                conn.commit()
            else:
                non_existing_queries.append(query_id)

    if len(non_existing_queries) > 0:
        logging.warning(f'For some reason the following queries do not exist anymore:')
        logging.warning(non_existing_queries)
    logging.info(f'Category "{category_name}" was inserted with Success !')


def get_cx_version(cx_server, verify_certs):
    logging.info(f'Retrieving Checkmarx Version from {cx_server}...')
    cx_version = "8.9"
    res = requests.get(f'{cx_server}/cxrestapi/system/version', verify=verify_certs)
    logging.debug(res)
    if res.status_code == 200:
        body = res.json()
        logging.info(f'Checkmarx Version: {body["version"]}')
        cx_version = body["version"]
    else:
        logging.warning(f'Cannot retrieve version from {cx_server}/cxrestapi/system/version')
        logging.info(f'Using Default Checkmarx Version: {cx_version}')
    return cx_version


def get_oauth_token(cx_server, cx_user, cx_password, verify_certs):
    logging.info(f'Retrieving OAuth Token from {cx_server} with user "{cx_user}"...')
    oauth_data = {
        "username": cx_user,
        "password": cx_password,
        "grant_type": 'password',
        "scope": 'sast_api',
        "client_id": 'resource_owner_sast_client',
        "client_secret": '014DF517-39D1-4453-B7B3-9930C563627C'
    }
    res = requests.post(f'{cx_server}/cxrestapi/auth/identity/connect/token', data=oauth_data, verify=verify_certs,
                        timeout=DEFAULT_TIMEOUT)
    logging.debug(res)
    if res.status_code == 200:
        try:
            json = res.json()
            token = f'{json["token_type"]} {json["access_token"]}'
            logging.debug(token)
            return token
        except JSONDecodeError:
            raise ConnectionError(f'Failed to login to server: {cx_server}/cxrestapi/auth/identity/connect/token, with user "{cx_user}"')
    else:
        raise ConnectionError(f'Failed to login to server: {cx_server}/cxrestapi/auth/identity/connect/token, with user "{cx_user}" : {res.json()}')


def get_soap_client(cx_server, cx_user, cx_password, verify_certs, cx_version):
    logging.info(f'Retrieving SOAP Client from {cx_server}...')
    cx_wsdl_url = f'{cx_server}/CxWebInterface/Portal/CxWebService.asmx?wsdl'
    session = Session()
    session.verify = verify_certs
    transport = Transport(session=session, timeout=DEFAULT_TIMEOUT)
    if cx_version.startswith("8."):
        client = Client(cx_wsdl_url, transport=transport)
    else:
        token = get_oauth_token(cx_server, cx_user, cx_password, verify_certs)
        settings = Settings(extra_http_headers={'Authorization': token})
        client = Client(cx_wsdl_url, transport=transport, settings=settings)
    return client.service


def get_db_connection(driver, db_server, db_user, db_password):
    logging.info(f'Trying to connect to "{db_server}" Database')
    if is_str(driver) and \
            is_str(db_server) and \
            is_str(db_user) and \
            is_str(db_password):
        try:
            conn = pyodbc.connect(
                'DRIVER={' + driver + '};SERVER=' + db_server +
                ';DATABASE=CxDB' +
                ';UID=' + db_user +
                ';PWD=' + db_password,
                timeout=DB_TIMEOUT)
            logging.info(f'Connection to "{db_server}" Database made with Success!')
            return conn
        except pyodbc.OperationalError or \
               pyodbc.InterfaceError or \
               pyodbc.Error as error:
            raise ConnectionError(error)
    else:
        raise AttributeError(
            "server | user | password | database were not provided")


def get_args(args):
    args_parser = argparse.ArgumentParser(prog=__app__, description=__app__)
    args_parser.add_argument('-v', '--version', help='Version', action='version', version=__version__)
    args_parser.add_argument('-cxu', '--cxuser', help='Checkmarx Username', required=False, default=__cx_username__)
    args_parser.add_argument('-cxp', '--cxpassword', help='Checkmarx Password', required=False, default=__cx_password__)
    args_parser.add_argument('-cxs', '--cxserver', help='Checkmarx Server URL', required=False, default=__cx_server__)
    args_parser.add_argument('-dbu', '--dbuser', help='Database Username', required=False, default=__db_username__)
    args_parser.add_argument('-dbp', '--dbpassword', help='Database Password', required=False, default=__db_password__)
    args_parser.add_argument('-dbs', '--dbserver', help='Database Server URL', required=False, default=__db_server__)
    args_parser.add_argument('-dbd', '--dbdriver', help='Checkmarx MSSQL DB Driver', required=False,
                             default=__db_driver__)
    args_parser.add_argument('-cn', '--categoryname', help='Category Name', required=False, default=__category_name__)
    args_parser.add_argument('-cgp', '--categorygroupprefix', help='Category Group Prefix', required=False,
                             default=__category_group_prefix__)
    args_parser.add_argument('-ucn', '--unknowncwename', help='Unknown CWE Name', required=False,
                             default=__unknown_cwe_name__)
    args_parser.add_argument('-d', '--debug', help='Enable Debug', action='store_true', required=False,
                             default=_debug_)
    args_parser.add_argument('-tc', '--trustcerts', help='Trust Certificates', action='store_true', required=False,
                             default=__trustcerts__)
    return args_parser.parse_args(args)


def main(args):
    if args:
        logging.debug(args)
        debug = args.debug
        if debug:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO

        logging.config.fileConfig('logging.conf')
        logging.getLogger().setLevel(log_level)

        cx_user = args.cxuser
        cx_password = args.cxpassword
        cx_server = args.cxserver
        db_user = args.dbuser
        db_password = args.dbpassword
        db_server = args.dbserver
        db_driver = args.dbdriver
        category_name = args.categoryname
        category_group_prefix = args.categorygroupprefix
        unknown_cwe_name = args.unknowncwename
        verify_certs = not args.trustcerts

        logging.info(f'[START] {__app__} - {__version__}')
        logging.info(SEPARATOR)
        logging.info("Arguments:")
        logging.info(f'\tSHORT_FLAG | LONG_FLAG | ENV_VAR : VALUE')
        logging.info(f'\t-cxs | --cxserver | CX_SERVER : {cx_server}')
        logging.info(f'\t-cxu | --cxuser | CX_USER : {cx_user}')
        logging.info(f'\t-cxp | --cxpassword | CX_PASSWORD : {MASKED_PASSWORD} (masked)')
        logging.info(f'\t-dbs | --dbserver | DB_SERVER : {db_server}')
        logging.info(f'\t-dbu | --dbuser | DB_USER : {db_user}')
        logging.info(f'\t-dbp | --dbpassword | DB_PASSWORD : {MASKED_PASSWORD} (masked)')
        logging.info(f'\t-dbd | --dbdriver | DB_DRIVER : {db_driver}')
        logging.info(f'\t-cn | --categoryname | CATEGORY_NAME : {category_name}')
        logging.info(f'\t-cgp | --categorygroupprefix | CATEGORY_GROUP_PREFIX : {category_group_prefix}')
        logging.info(f'\t-ucn | --unknowncwename | UNKNOWN_CWE_NAME : {unknown_cwe_name}')
        logging.info(f'\t-d | --debug | DEBUG : {str(debug)}')
        logging.info(f'\t-tc | --trustcerts | TRUST_CERTS : {str(args.trustcerts)}')
        logging.info(SEPARATOR)

        cx_version = get_cx_version(cx_server, verify_certs)

        logging.debug(cx_version)
        logging.info(SEPARATOR)
        service = get_soap_client(cx_server, cx_user, cx_password, verify_certs, cx_version)
        if cx_version.startswith("8."):
            session_id = cx_login(cx_server, service, cx_user, cx_password)
        else:
            session_id = None

        logging.info(SEPARATOR)
        query_groups = get_queries(service, session_id, cx_version)
        logging.debug(query_groups)
        category_object = get_queries_categories_object(query_groups, category_name, category_group_prefix,
                                                        unknown_cwe_name)
        logging.debug(category_object)
        logging.info(SEPARATOR)
        conn = get_db_connection(db_driver, db_server, db_user, db_password)

        logging.info(SEPARATOR)
        category_type_id = check_category(conn, category_name)
        logging.debug(category_type_id)
        clean_category_data(conn, category_type_id, category_name)
        insert_category_data(conn, category_name, category_type_id, category_object)

        logging.info(SEPARATOR)
        logging.info(f'[END] {__app__} - {__version__}')
    else:
        raise ValueError("Missing Arguments")


if __name__ == '__main__':
    main(get_args(sys.argv[1:]))
