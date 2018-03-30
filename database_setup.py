from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key = True)
    name = Column(String(30), nullable = False, unique= True)
    email = Column(String(30), nullable = False, unique =True)
    picture = Column(String(250))

class Restaurant(Base):
    __tablename__ = 'restaurant'
    user_id = Column(Integer, ForeignKey('user.id'))
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }

class MenuItem(Base):
    __tablename__ = 'menu_item'

    user_id = Column(Integer, ForeignKey('user.id'))
    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    price = Column(String(8))
    course = Column(String(250))
    restaurant_id = Column(Integer,ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)
    user = relationship(User)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'         : self.description,
           'id'         : self.id,
           'price'         : self.price,
           'course'         : self.course,
       }






engine = create_engine('postgresql+psycopg2://bhanu:bhanu@localhost/restaurant')


Base.metadata.create_all(engine)
