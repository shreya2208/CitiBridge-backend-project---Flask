
from database import db
from flask_security import Security
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_restful import fields, marshal_with
# Create app
app = Flask(__name__)
cors = CORS(app,  resources={r"/api/*": {"origins": "*"}}, headers='Content-Type', methods=["GET", "POST", "DELETE"])
import os

app.config['DEBUG'] = True

# Generate a nice key using secrets.token_urlsafe()
app.config['SECRET_KEY'] = os.environ.get(
  "SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
# Generate a good salt using: secrets.SystemRandom().getrandbits(128)
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get(
  "SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')
app.config['SECURITY_PASSWORD_SALT'] = 'bcrypt'
# have session and remember cookie be samesite (flask/flask_login)
app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
app.config["SESSION_COOKIE_SAMESITE"] = "strict"
app.config["SECURITY_REGISTRABLE"] = False 
#app.config["SECURITY_SEND_REGISTER_EMAIL"] = True
app.config["SECURITY_UNAUTHORIZED_VIEW"] = None
# Use an in-memory db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marketcaptrade.db'
# As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
# underlying engine. This option makes sure that DB connections from the
# pool are still valid. Important for entire application since
# many DBaaS options automatically close idle connections.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
  "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.security = Security(app)
db.init_app(app)
app.app_context().push()
from datetime import datetime, timedelta

# imports for PyJWT authentication
import jwt
from flask import g, request
from flask_restful import Api, Resource
from models import User, Favourites


api = Api(app)

class LoginAPI(Resource):
  @cross_origin(origins="http://localhost:5173", methods=["POST"])
  def post(self):
    # creates dictionary of form data
    auth = request.authorization
    print(auth.get('username'), auth.get('password'))
    if not auth or not auth.get('username') or not auth.get('password'):
      # returns 401 if any email or / and password is missing
      return 'Could not verify', 401, {
        'WWW-Authenticate': 'Basic realm ="Login required !!"'
      }

    user = User.query\
        .filter_by(username = auth.get('username'))\
        .first()

    if not user:
      # returns 401 if user does not exist
      return 'Could not verify', 401, {
        'WWW-Authenticate': 'Basic realm ="User does not exist !!"'
      }
    g.current_user = user
    match =(user.password  == auth.get('password'))
    if match:
  # generates the JWT Token
        token = jwt.encode(
          {
            'public_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
          }, app.config['SECRET_KEY'])

        g.current_user = user
        return {'token': token}, 201
    # returns 403 if password is wrong
    return 'Could not verify', 403, {
      'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'
    }

favourite = {
    'symbol' : fields.String,
    'timestamp' : fields.DateTime
    
}
class UserFavouritesAPI(Resource):
    @cross_origin(origins="http://localhost:5173", methods=["GET"])
    def get(self):
        username = request.args.get('username')
        print(username)
        user = User.query\
            .filter_by(username = username)\
            .first()
        print(user)
        output_list = []
        favourites = Favourites.query.filter_by(user_id=user.id).all()
        for f in favourites:
           output_list.append({
               'symbol' : f.symbol,
               'timestamp' : f.timestamp,
               'current_market_price' : f.current_market_price,
               'qty' : f.qty
           })
        print(output_list)
        return output_list, 200
      
    @cross_origin(origins="http://localhost:5173", methods=["POST"])
    def post(self):
      username = request.args.get('username')
      print(username)
      user = User.query\
            .filter_by(username = username)\
            .first()
      symbol = request.form.get('symbol')
      current_market_price = request.form.get('current_market_price')
      qty = int(request.form.get('qty'))
      print(symbol)
      favourite = Favourites(user_id=user.id, symbol=symbol, current_market_price=current_market_price, qty=qty)
      db.session.add(favourite)
      db.session.commit()
      return 'Successfuly saved', 200
        
    @cross_origin(origins="http://localhost:5173", methods=["DELETE"])
    def delete(self):
      username = request.args.get('username')
      symbol = request.args.get('symbol')
      user = User.query\
            .filter_by(username = username)\
            .first()
      favourite = Favourites.query.filter_by(user_id = user.id, symbol=symbol).first()
      db.session.delete(favourite)
      db.session.commit()
      return 'Successfully deleted', 200
    
    
api.add_resource(UserFavouritesAPI, '/api/user/favourites')



api.add_resource(LoginAPI,'/api/login')



@app.route('/')
def index():
  return 'Hello from Flask!'

app.run(host='0.0.0.0', port=8081)

