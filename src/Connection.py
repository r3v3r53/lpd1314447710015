 # -*- coding: utf-8 -*-
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import hashlib

"""
Usage Example.
con = Connection('username', 'password')
engine = con.engine
engine.connect()
"""
class Connection:
    
    def __init__(self, username, password):
        """
        o nome da base de dados tem como origem
        a operacao xor entre o username e a password
        o hash md5 dessa operacao fica o nome da base de dados        
        @param  username: username
        @param password: password
        """
        try:
            self.engine = self.__conDB(username, password)
            self.engine.connect()
            Session = sessionmaker(bind=self.engine)
            Session.configure(bind=self.engine)
            self.session = Session()
        except:
            print "error creating database"
            raise

    def add(self, x):
        self.session.add(x)
        print x

    def commit(self):
        self.session.commit()

    def __conDB(self, username, password):
        # baseado em http://stackoverflow.com/questions/2612720/how-to-do-bitwise-exclusive-or-of-two-strings-in-python
        db = ''.join(chr(ord(a) ^ ord(b))
                     for a,b in zip(username,password))
        m = hashlib.md5()
        m.update(db)
        return create_engine('sqlite:///%s.db' % (m.hexdigest()))
