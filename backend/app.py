import datetime 
import json
import os
import jwt
import time
from functools import wraps
from flask import Flask, current_app, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret_secret_key'

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///samp.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# CORS configuration
CORS(app)

# Directory for file uploads
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



# Define SQLAlchemy models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    img = db.Column(db.String(100))
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    riter = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    img = db.Column(db.String(100))
    type = db.Column(db.Integer, nullable = False)
    lend = db.Column(db.Boolean, default=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('books', lazy=True))

class Lend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="lends")
    book_id = db.Column(db.Integer, db.ForeignKey("book.id"), nullable=False)
    book = db.relationship("Book", backref="lends")
    borrowed_at = db.Column(db.DateTime, nullable=False)
    return_at = db.Column(db.DateTime, nullable=False)


# Helper functions
def generate_token(user_id):
    expiration = int(time.time()) + 3600  # Set expiration time to 1 hour from now
    payload = {'user_id': user_id, 'exp': expiration}
    token = jwt.encode(payload, 'secret-secret-key', algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user_id, *args, **kwargs)

    return decorated

# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    # Check if the user exists
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Generate an access token with expiration time
        expires = datetime.timedelta(hours=1)
        access_token = create_access_token(identity=user.id, expires_delta=expires)

        # Get the image URL associated with the user
        image_url = f"{request.url_root}{UPLOAD_FOLDER}/{user.img}"

        return jsonify({'access_token': access_token, 'username': username, 'image_url': image_url}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route to serve uploaded files
@app.route('/uploads/books/<filename>')
def uploaded_file_book(filename):
    return send_from_directory(app.config['BOOK_UPLOAD_FOLDER'], filename)

# Define the upload folder for book images
BOOK_UPLOAD_FOLDER = 'uploads/books'

# Update the configuration to set the upload folder
app.config['BOOK_UPLOAD_FOLDER'] = BOOK_UPLOAD_FOLDER



@app.route('/addbook', methods=['POST'])
@jwt_required()
def addbook():
    current_user_id = get_jwt_identity()

    # Check if the current user has the role "manager"
    current_user = User.query.get(current_user_id)
    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to add books'}), 403

    # Extract book details from the request
    book_name = request.form.get('book_name')
    riter = request.form.get('riter')
    date = request.form.get('date')
    type = request.form.get('type')

    # Get the uploaded file
    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)

        # Save the file to the server
        filepath = os.path.join(app.config['BOOK_UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Create a new book and add it to the database
        new_book = Book(name=book_name, riter=riter, date=date, type=type ,img=filename, userid=current_user_id)
        db.session.add(new_book)
        db.session.commit()

        return jsonify({'message': 'Book created successfully'}), 201
    else:
        return jsonify({'error': 'No image file provided'}), 400


# Route to get all books
# Modify the route to fetch book information to include user name if it is lent
# Modify the route to fetch book information to include return date if it is lent
from flask import request, jsonify




@app.route('/getbooks', methods=['GET'])
def get_books():
    try:
        books = Book.query.all()
        books_list = []
        for book in books:
            book_data = {
                'book_id': book.id,
                'book_name': book.name,
                'riter': book.riter,
                'date': book.date,
                'img_url': f"{request.url_root}{BOOK_UPLOAD_FOLDER}/{book.img}",  # Construct image URL
                'lend': book.lend,
                'type': book.type
            }
            if book.lend:
                lend_info = Lend.query.filter_by(book_id=book.id).first()
                if lend_info:
                    user_info = {
                        'user_name': 'Unknown'  # Default if user is not found
                    }
                    user = User.query.get(lend_info.user_id)
                    if user:
                        user_info['user_name'] = user.username
                    book_data['lender'] = user_info['user_name']
                    book_data['return_date'] = lend_info.return_at.strftime('%Y-%m-%d')
            books_list.append(book_data)
        return jsonify({'books': books_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500





# Route to delete a book
@app.route('/deletebook/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    current_user_id = get_jwt_identity()

    # Check if the current user has the role "manager"
    current_user = User.query.get(current_user_id)
    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete books'}), 403

    # Ensure the user deleting the book is the owner
    userid = get_jwt_identity()
    book_to_delete = Book.query.filter_by(id=book_id).first()

    if not book_to_delete:
        return jsonify({'error': 'Book not found or user does not have permission to delete'}), 404

    # Delete the book from the database
    db.session.delete(book_to_delete)
    db.session.commit()

    return jsonify({'message': 'Book deleted successfully'}), 200




from werkzeug.security import generate_password_hash

@app.route('/updateuser/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    try:
        # Ensure the authenticated user is an admin or has appropriate permissions
        current_user_id = get_jwt_identity()

    # Check if the current user has the role "manager"
        current_user = User.query.get(current_user_id)
        if current_user.role != "1":
            return jsonify({'error': 'Only managers are allowed to update users'}), 403
            


        # Fetch user details from the request body
        updated_user_info = request.json
        
        # Find the user to be updated
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update user details
        user.username = updated_user_info.get('username', user.username)
        user.role = updated_user_info.get('role', user.role)
        # password = request.form.get('password')

    # Hash and salt the new password using Bcrypt
        # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # user.password = updated_user_info.get('password', hashed_password)

        # Commit changes to the database
        db.session.commit()

        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to register a new user
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    # Get the uploaded file
    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)

    # Save the file to the server
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

    # Check if the username is already taken
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username is already taken'}), 400

    # Hash and salt the password using Bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user and add to the database
    new_user = User(username=username, password=hashed_password, role=role, img=filename)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

# Route to lend a book
from datetime import timedelta

@app.route('/lendbook', methods=['POST'])
@jwt_required()
def lend_book():
    try:
        user_id = get_jwt_identity()
        book_id = request.json.get('book_id')

        user = User.query.get(user_id)
        book = Book.query.get(book_id)
        if not user or not book:
            return jsonify({'error': 'Invalid user or book'}), 404

        if book.lend:
            return jsonify({'error': 'Book is already lent'}), 409

        current_time = datetime.datetime.now()

        # Define return date based on book type
        if book.type == 1:
            return_days = 10
        elif book.type == 2:
            return_days = 5
        elif book.type == 3:
            return_days = 2
        else:
            return jsonify({'error': 'Invalid book type'}), 400

        return_at = current_time + timedelta(days=return_days)

        lend = Lend(user_id=user_id, book_id=book_id, borrowed_at=current_time, return_at=return_at)

        # Add the lend object to the session
        db.session.add(lend)
        
        # Commit the changes to the database session
        db.session.commit()

        # Update the book's lend status
        book.lend = True
        db.session.commit()

        return jsonify({'message': 'Book lent successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500



# Route to get all users
@app.route('/getusers', methods=['GET'])
def get_users():
    try:
        # Fetch all users from the database
        users = User.query.all()

        # Convert user data to a list of dictionaries
        users_list = [{'id': user.id, 'username': user.username, 'password': user.password, 'role': user.role} for user in users]

        return jsonify({'users': users_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to update a book
@app.route('/updatebook/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    current_user_id = get_jwt_identity()

    # Check if the current user has the role "manager"
    current_user = User.query.get(current_user_id)
    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to update books'}), 403

    try:
        book_to_update = Book.query.filter_by(id=book_id).first()

        if not book_to_update:
            return jsonify({'error': 'Book not found or user does not have permission to update'}), 404

        # Get updated book details from the request data
        updated_name = request.json.get('name', book_to_update.name)
        updated_riter = request.json.get('riter', book_to_update.riter)
        updated_date = request.json.get('date', book_to_update.date)
        updated_type = request.json.get('type', book_to_update.type)


        # Update the book details
        book_to_update.name = updated_name
        book_to_update.riter = updated_riter
        book_to_update.date = updated_date
        book_to_update.type = updated_type


        # Commit changes to the database
        db.session.commit()

        return jsonify({'message': 'Book updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Route to return a book
@app.route('/returnbook/<int:book_id>', methods=['POST'])
@jwt_required()
def return_book(book_id):
    try:
        current_user_id = get_jwt_identity()

        # Check if the lending record exists for the specified book and user
        lend_record = Lend.query.filter_by(book_id=book_id, user_id=current_user_id).first()
        if not lend_record:
            return jsonify({'error': 'User is not authorized to return this book'}), 403

        # Update the book's lend status and remove the lending record
        book = lend_record.book
        book.lend = False
        db.session.delete(lend_record)
        db.session.commit()

        return jsonify({'message': 'Book returned successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to delete a user
@app.route('/deleteuser/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()

    # Check if the current user has the role "manager"
    current_user = User.query.get(current_user_id)
    if current_user.role != "1":
        return jsonify({'error': 'Only managers are allowed to delete users'}), 403

    # Ensure the user to be deleted exists
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'error': 'User not found'}), 404

    # Delete the user from the database
    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
