# baseado em http://docs.sqlalchemy.org/en/rel_0_9/orm/tutorial.html

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from Connection import Connection

Base = declarative_base()

class IP(Base):
    __tablename__ = 'ips'
    id = Column(Integer, primary_key=True)
    address = Column(String)

    def create(self, engine):
        Base.metadata.create_all(engine)

    def __repr__(self):
        return "<IP(id='%s', address='%s'>" % (self.id, self.address)
