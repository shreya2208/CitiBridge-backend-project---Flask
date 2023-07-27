from database import db
from flask_security import RoleMixin, SQLAlchemyUserDatastore, UserMixin

class User(db.Model, UserMixin):
  __tablename__ = 'User'
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  password = db.Column(db.String(120), unique=False, nullable=False)
 
class Favourites(db.Model):
  __tablename__ = 'Favourites'
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  user_id =  db.Column(db.Integer(), db.ForeignKey('User.id'))
  symbol = db.Column(db.String(25))
  timestamp = db.Column(db.String(255))
  current_market_price = db.Column(db.String())
  qty = db.Column(db.Integer())
