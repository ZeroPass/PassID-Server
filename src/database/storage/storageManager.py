'''
    File name: storageManager.py
    Author: ZeroPass - Nejc Skerjanc
    License: MIT lincense
    Python Version: 3.6
'''

import sqlalchemy
from sqlalchemy import Table, Column, Integer, BigInteger, String, DateTime, MetaData, LargeBinary, Boolean
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.sql import func

#creating base class from template
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class ConnectionError(Exception):
    pass

"""Database structures"""
metadata = MetaData()
certificateRevocationListDB = Table('certificateRevocationList', metadata,
                            Column('id', Integer, primary_key=True),
                            Column('object', LargeBinary),
                            Column('issuerCountry', String),
                            Column('size', Integer),
                            Column('thisUpdate', DateTime),
                            Column('nextUpdate', DateTime),
                            Column('signatureAlgorithm', String),
                            Column('signatureHashAlgorithm', String)
                            )

documentSignerCertificate = Table('documentSignerCertificate', metadata,
                            Column('id', Integer, primary_key=True),
                            Column('object', LargeBinary),
                            Column('issuer', String),
                            Column('serialNumber', String),
                            Column('fingerprint', String),
                            Column('thisUpdate', DateTime),
                            Column('nextUpdate', DateTime),
                            Column('subject', String),
                            Column('subjectKey', LargeBinary),
                            Column('authorityKey', LargeBinary)
                            )

cscaCertificate = Table('CSCACertificate', metadata,
                            Column('id', Integer, primary_key=True),
                            Column('object', LargeBinary),
                            Column('issuer', String),
                            Column('serialNumber', String),
                            Column('fingerprint', String),
                            Column('thisUpdate', DateTime),
                            Column('nextUpdate', DateTime),
                            Column('subject', String),
                            Column('subjectKey', LargeBinary),
                            Column('authorityKey', LargeBinary)
                            )

challenge = Table('userChallenge', metadata,
                            Column('id', String, primary_key=True),
                            Column('challenge', String),
                            Column("createTime", DateTime(timezone=True), default=func.now())
                            )

account = Table('account', metadata,
                            Column('uid', LargeBinary, primary_key=True), # uid = UserId
                            Column('sod', LargeBinary, nullable=False),
                            Column('aaPublicKey', LargeBinary, nullable=False),
                            Column('sigAlgo', LargeBinary, nullable=True),
                            Column('dg1', LargeBinary, nullable=True),
                            Column('validUntil', DateTime),
                            Column('loginCount', Integer, default=0),
                            Column('isValid', Boolean)
                            )

class Connection:
    """Manage ORM connection to save/load objects in database"""

    connectionObj = None
    metaData = None
    session = None

    def __init__(self, user: str, password: str, db: str, host='localhost', port=5432):
        """When we initialize the instance we meed to send connneciton and metadata instances to the object"""
        try:
            # We connect with the help of the PostgreSQL URL
            url = 'postgresql://{}:{}@{}:{}/{}'
            url = url.format(user, password, host, port, db)

            # The return value of create_engine() is our connection object
            self.connectionObj = sqlalchemy.create_engine(url, client_encoding='utf8', echo=True)

            # We then bind the connection to MetaData()
            self.metaData = sqlalchemy.MetaData(bind=self.connectionObj, reflect=True)

            # we create session object to use it later
            Session = sessionmaker(bind=self.connectionObj)
            self.session = Session()

            self.initTables()

        except Exception as e:
            raise ConnectionError("Connection failed.")

    def getEngine(self):
        """ It returns engline object"""
        return self.connectionObj

    def getSession(self):
        """ It returns session to use it in the acutual storage objects/instances"""
        return self.session

    def initTables(self):
        """Initialize tables for usage in database"""

        #imports - to avoid circle imports
        from database.storage.certificateRevocationListStorage import CertificateRevocationListStorage
        from database.storage.x509Storage import DocumentSignerCertificateStorage, CSCAStorage
        from database.storage.challengeStorage import ChallengeStorage
        from database.storage.accountStorage import AccountStorage

        #CertificateRevocationList
        mapper(CertificateRevocationListStorage, certificateRevocationListDB)

        #DocumentSignerCertificate
        mapper(DocumentSignerCertificateStorage, documentSignerCertificate)

        # CSCAStorage
        mapper(CSCAStorage, cscaCertificate)

        # challenge
        mapper(ChallengeStorage, challenge)

        # account
        mapper(AccountStorage, account)

        #creating tables
        Base.metadata.create_all(self.connectionObj, tables=[certificateRevocationListDB, documentSignerCertificate, cscaCertificate, challenge, account])


def truncateAll(connection: Connection):
    """Truncate all tables"""
    try:
        sql_raw_query = 'select \'TRUNCATE table "\' || tablename || \'" cascade;\' from pg_tables where schemaname=\'public\';'
        for result in connection.getEngine().execute(sql_raw_query):
            connection.getEngine().execute(result[0])
    except Exception as e:
        raise IOError("Problem deleting object" + e)

