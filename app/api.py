from flask import Flask
from flask_restful import Resource, Api, reqparse, marshal, fields
from flask_cors import CORS

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, insert, ForeignKey, DateTime, distinct, func
from sqlalchemy.orm import relationship
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_claims, jwt_required, get_jwt_identity, get_raw_jwt
from functools import wraps
import sys, json, datetime, math
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

app = Flask(__name__)
CORS(app, resources={r"*":{"origin":"*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://hasan:alphatech123@127.0.0.1/Portofolio'
app.config['JWT_SECRET_KEY'] = 'this is secret'


db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
jwt = JWTManager(app)

api = Api(app)

# Check if claims in token is admin, so it's is admin
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'admin':
            # if not admin
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # if admin
            return fn(*args, **kwargs)
    return wrapper

# Check if claims in token is pelapak,
def pelapak_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'pelapak':
            # if not pelapak
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # if pelapak
            return fn(*args, **kwargs)
    return wrapper

# Model Users: save users data, admin or pelapak
class Users(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(255), nullable= False)
    username = db.Column(db.String(255), nullable= False)
    email = db.Column(db.String(255), unique= True, nullable= False)
    password = db.Column(db.String(255), nullable= False)
    no_telp = db.Column(db.String(255))
    address = db.Column(db.String(255))
    type = db.Column(db.String(30), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    tool =  db.relationship('Tools', backref='users')

    def __repr__(self):
        return '<Users %r>' % self.id

# Model Tools: save books data, FK with author data
class Tools(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    tool_name = db.Column(db.String(255), nullable= False)
    category = db.Column(db.Integer, db.ForeignKey("category.id"), nullable= False)
    price = db.Column(db.Integer, nullable = False)
    stock = db.Column(db.Integer)
    url_picture= db.Column(db.String(255))
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    #foreign key
    user_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable= False)


    def __repr__(self):
        return '<Tools %r>' % self.id

class Category(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(255), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    tool = db.relationship("Tools", backref='tool_category')

    def __repr__(self):
        return '<Category %r>' % self.id

# Resource to get the JWT token 
class LoginResource(Resource):
    # auth, just user with pelapak token can access this method 
    @pelapak_required
    def get(self):
        # get user identity from token by claims 
        current_user = get_jwt_identity()

        # find data user by user identity (id users from token by claims)
        qty= Users.query.get(current_user)
        data = {
            "name": qty.name,
            "username": qty.username,
            "email": qty.email,
            "password": qty.password,
            "no_telp": qty.no_telp,
            "address": qty.address
        }
        return data, 200

    # method to get jwt token for pelapak already have account
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', location= 'json', required= True)
        parser.add_argument('password', location= 'json', required= True)

        args = parser.parse_args()

        # get data users by username and password
        qry = Users.query.filter_by( username= args['username'], password= args['password']).first()
        
        # check whether the user with the username and password entered already has an account
        if qry == None:
            # if not return 401
            return {"message": "UNAUTHORIZED"}, 401
        
        # if have account create token for him
        token = create_access_token(identity= qry.id, expires_delta = datetime.timedelta(days=1))

        # then return to him
        return {"token": token}, 200

# Resource to register your account
class RegisterResource(Resource):
    def post(self):
        # collect data from body 
        parser = reqparse.RequestParser()
        parser.add_argument('name', type= str, location='json', required= True, help= 'name must be string and exist')
        parser.add_argument('username', type= str, location='json', required= True, help= 'username must be string and exist')
        parser.add_argument('email', type= str, location='json', required= True, help= 'email must be string and exist')
        parser.add_argument('password', type= str, location='json', required=True, help= 'password must be string and exist')
        parser.add_argument('address', type= str, location='json', required=True, help= 'address must be string and exist')
        parser.add_argument('no_telp', type= str, location='json', required=True, help= 'no_telp must be string and exist')
        parser.add_argument('secret', type= str, location='json', required=False, help= 'secret must be string')

        mySecret = "ADMIN"
        # parse it in args variable
        args = parser.parse_args()

        # find user data by username
        qry= Users.query.filter_by(username= args['username']).first()
        # if username already taken
        if qry != None:
            return {"message": "Username telah digunakan"}, 406

        # check by email
        qry= Users.query.filter_by(email= args['email']).first()
        if qry != None:
            # if email has taken
            return {"message": "Email telah digunakan"}, 406

        # if username and email available then check its admin or pelapak
        if(args["secret"] != None and args["secret"] == mySecret):
            auth = 'admin'
        else:
            auth = 'pelapak'

        data = Users(
                name= args['name'], 
                username= args['username'], 
                email= args['email'], 
                password= args['password'], 
                address= args['address'], 
                no_telp= args['no_telp'], 
                type= auth
            )

        db.session.add(data)
        db.session.commit()

        # create token
        token = create_access_token(identity= data.id, expires_delta = datetime.timedelta(days=1))
        return {"message": "SUCCESS" , "token": token}, 200

        # create claims to user token
@jwt.user_claims_loader
def add_claim_to_access_token_uhuyy(identity):
    # find users data by identity field in token
    data = Users.query.get(identity)
    # add 'type' as key and type from db as value 
    return { "type": data.type }

class PelapakResource(Resource):
    # field yang akan ditampilkan lewat marshal
    tool_field= {
        "id": fields.Integer,
        "tool_name": fields.String, 
        "category": fields.String,
        "price": fields.Integer,
        "stock": fields.Integer,
        "url_picture": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "users.name": fields.String
    }
    
    @pelapak_required
    def get(self, id= None):
        # get identity from user token
        current_user = get_jwt_identity()

        ans = {}
        ans["message"] = "SUCCESS"
        rows = []

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Tools.query.filter_by(user_id = current_user, id = id).first()
            # if not found data
            if(qry == None):
                # return message
                return {'message': 'Data not found !!!'}, 404
            # if found data
            rows = marshal(qry, self.tool_field)
            ans["data"] = rows
            # return data
            return ans, 200

        # if id params stil None (nothing data from id params), get all data on pelapak id 
        qry = Tools.query.filter_by(user_id = current_user)
        
        for row in qry.all():
            # collect all data to rows
            rows.append(marshal(row, self.tool_field))
        
        ans["data"] = rows

        # return all data
        return ans, 200

    @pelapak_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("tool_name", type= str, help= 'tool_name key must be an string and exist', location= 'json', required= True)
        parser.add_argument("category", type= str, help= 'category must be an string and exist', location= 'json', required= True)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= True)
        parser.add_argument("stock", type= int, help= 'stock must be an integer and exist', location= 'json', required= True)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False, default= 'default pict')

        args = parser.parse_args()

        # get identity from token
        current_user = get_jwt_identity()

        # insert all data
        data = Tools(
                tool_name= args["tool_name"],
                category= args["category"],
                price= args["price"],
                stock= args["stock"],
                url_picture= args["url_picture"],
                user_id= current_user
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @pelapak_required
    def patch(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data where on id
        data = Tools.query.filter_by(user_id = current_user, id = id).first()

        # if not have data
        if(data == None): 
            # return not found
            return {'message': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("tool_name", type= str, help= 'tool_name key must be an string and exist', location= 'json', required= False)
        parser.add_argument("category", type= str, help= 'category name must be an string and exist', location= 'json', required= False)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= False)
        parser.add_argument("stock", type= int, help= 'stock must be an integer and exist', location= 'json', required= False)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False)
        args = parser.parse_args()

        # update the data
        if args["tool_name"] != None:
            data.tool_name= args["tool_name"]
        if args["category"] != None:
            data.category= args["category"]
        if args["price"] != None:
            data.price= args["price"]
        if args["stock"] != None:
            data.stock= args["stock"]
        if args["url_picture"] != None:
            data.url_picture= args["url_picture"]

        # update updatedAt field when update data
        data.updatedAt = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @pelapak_required
    def delete(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data
        data = Tools.query.filter_by(user_id = current_user, id = id).first()

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200

class PublicResource(Resource):
    # field yang ingin di tampilkan lewat marshal
    tool_field= {
        "id": fields.Integer,
        "tool_name": fields.String, 
        "category": fields.String,
        "tool_category.name":fields.String,
        "price": fields.Integer,
        "stock": fields.Integer,
        "url_picture": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "user_id": fields.String,    
        "users.name": fields.String   
    }
    
    def get(self, id = None):

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Tools.query.get(id)
            # if not found data
            if(qry == None):
                # return message
                return {'message': 'Data not found !!!'}, 404
            # if found data
            ans = {
                "page": 1,
                "total_page": 1,
                "per_page": 25,
                "data": []
            }

            rows = marshal(qry, self.tool_field)
            ans["data"] = rows
            # return data
            return ans, 200

        parser = reqparse.RequestParser()
        parser.add_argument("p", type= int, location= 'args', default= 1)
        parser.add_argument("rp", type= int, location= 'args', default= 25)
        #filter,  query where
        parser.add_argument("id",type= int, help= 'id must be an integer', location= 'args')
        parser.add_argument("tool_name",type= str, help= 'tool_name must be an string', location= 'args')
        parser.add_argument("price",type= int, help= 'price must be an integer', location= 'args')
        parser.add_argument("stock",type= int, help= 'stock must be an integer', location= 'args')
        parser.add_argument("category",type= str, help= 'category must be an string', location= 'args')
        #order, query order by
        parser.add_argument("orderBy", help= 'invalid orderBy', location= 'args', choices=('id', 'tool_name', 'price', 'stock', 'category', 'createdAt', 'updatedAt'))
        parser.add_argument("sort", help= 'invalid sort value', location= 'args', choices=('asc', 'desc'), default = 'asc')

        args = parser.parse_args()

        qry = Tools.query

        if args['p'] == 1:
            offset = 0
        else:
            offset = (args['p'] * args['rp']) - args['rp']

        # query WHERE
        if args['id'] != None:
            qry = qry.filter_by(id = args['id'])
        if args["tool_name"] != None:
            qry = qry.filter_by(tool_name = args["tool_name"]) 
        if args["category"] != None:
            qry = qry.filter_by(category = args["category"]) 
        if args["price"] != None:
            qry = qry.filter_by(price = args["price"]) 
        if args["stock"] != None:
            qry = qry.filter_by(stock = args["stock"]) 

        
        # query ORDER BY
        if args['orderBy'] != None:

            if args["orderBy"] == "id":
                field_sort = Tools.id
            elif args["orderBy"] == "tool_name":
                field_sort = Tools.tool_name
            elif args["orderBy"] == "price":
                field_sort = Tools.price
            elif args["orderBy"] == "stock":
                field_sort = Tools.stock
            elif args["orderBy"] == "category":
                field_sort = Tools.category
            elif args["orderBy"] == "createdAt":
                field_sort = Tools.createdAt
            elif args["orderBy"] == "updatedAt":
                field_sort = Tools.updatedAt

            if args['sort'] == 'desc':
                qry = qry.order_by(desc(field_sort))
               
            else:
                qry = qry.order_by(field_sort)

        # query LIMIT, pagination
        
        rows= qry.count()
        qry =  qry.limit(args['rp']).offset(offset)
        tp = math.ceil(rows / args['rp'])
        
        ans = {
            "page": args['p'],
            "total_page": tp,
            "per_page": args['rp'],
            "data": []
        }

        rows = []
        for row in qry.all():
            rows.append(marshal(row, self.tool_field))

        ans["data"] = rows

        return ans, 200

class categoryResource(Resource):
    category_field = {
        "name" : fields.String,
        "createdAt" : fields.String,
        "updatedAt" : fields.String
    }

    def get(self):
        data = Category.query
        ans = {
            "message": "SUCCESS",
            "data": []
        }

        rows = []
        for row in data.all():
            rows.append(marshal(row, self.category_field))
        ans["data"] = rows
        return ans, 200
        
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'tool_name key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()

        data = Category.query.filter_by(category = args["category"]).first()
        if (data != None):
            return {"message": "Cannot duplicate category"}, 406

        data = Category(
                category= args["category"],
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200
    
    @admin_required
    def patch(self, id):
        data = Category.query.get(id)

        if(data == None):
            return {"message": "Data Not Found!"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'tool_name key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()
        data.category = args['category']
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @admin_required
    def delete(self, id):
        data = Category.query.get(id)

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200


# Users Endpoint
api.add_resource(LoginResource, '/api/users/login', '/api/users/me')
api.add_resource(RegisterResource, '/api/users/register')

# Pelapak Endpoint
api.add_resource(PelapakResource, '/api/users/items', '/api/users/items/<int:id>')

# Public Endpoint
api.add_resource(PublicResource, '/api/public/items', '/api/public/items/<int:id>' )

# category Endpoint
api.add_resource(categoryResource, '/api/public/category', '/api/public/category/<int:id>' )

@jwt.expired_token_loader
def exipred_token_message():
    return json.dumps({"message": "The token has expired"}), 401, {'Content-Type': 'application/json'}

@jwt.unauthorized_loader
def unathorized_message(error_string):
    return json.dumps({'message': error_string}), 401, {'Content-Type': 'application/json'}


if __name__ == "__main__":
    try:
        if sys.argv[1] == 'db':
            manager.run()
    except IndexError as identifier:
        app.run(debug=True, host='0.0.0.0', port=5000)