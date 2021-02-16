from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thissevret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///irithim.db'
db = SQLAlchemy(app)


# User MODEL
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(256), nullable=False, unique=True)
    password = db.Column(db.String(256))
    admin = db.Column(db.Boolean)


# List MODEL
class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, nullable=True)


# Card Model
class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), nullable=False)


# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    card_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String(256))

# Reply Model
class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    card_id = db.Column(db.Integer, nullable=False)
    comm_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String(256))


# db.create_all()

# Token Decorater
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is Invalid!!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# ROUTES
# GET ALL USERS
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)

    return jsonify({'users': output})


# Get Specific User
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No User Found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


# Create User
@app.route('/user', methods=['POST'])
# @token_required
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    
    user_data = {}
    user_data['public_id'] = new_user.public_id
    user_data['name'] = new_user.name
    user_data['password'] = new_user.password
    user_data['admin'] = new_user.admin

    return jsonify({'message': 'New User Created!', 'user': user_data})

# Update User
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No User Found!'})

    user.admin = True

    db.session.commit()

    return jsonify({'message': 'User Updated Successfully!'})


# Delete USer
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No User Found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User Has Been Deleted!'})


# LOGIN ROUTE
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'Token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})


################################################
################ LIST ROUTES ###################
################################################

# Assign Member to a List
@app.route('/assign-list/<list_id>/<user_id>', methods=['POST'])
@token_required
def assign_user(current_user, list_id, user_id):

    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})
    list = List.query.filter_by(id=list_id).first()
    if current_user.id == list.user_id:
        list.user_id = user_id
        db.session.commit()

        return jsonify({'message': 'List Assigned to a member successfully!'})
    else:
        return jsonify({'message': 'Not From Your Lists!'})
# UNAssign Member to a List
@app.route('/unassign-list/<list_id>', methods=['POST'])
@token_required
def un_assign_user(current_user, list_id):

    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})

    list = List.query.filter_by(id=list_id).first()
    if current_user.id == list.user_id:

        list.user_id = None
        db.session.commit()
        return jsonify({'message': 'List Un Assigned successfully!'})
    else:
        return jsonify({'message': 'Not From Your Lists!'})


#Get All Lists
@app.route('/list', methods=['GET'])
@token_required
def get_all_lists(current_user):
    if current_user.admin:

        lists = List.query.all()
        output = []
        for list in lists:
            list_data = {}
            list_data['title'] = list.title
            list_data['user_id'] = list.user_id
            output.append(list_data)

        return jsonify({'Lists': output})
    else:
        lists = List.query.filter_by(user_id=current_user.id).all()
        output = []
        for list in lists:
            list_data = {}
            list_data['title'] = list.title
            list_data['user_id'] = list.user_id
            output.append(list_data)

        return jsonify({'Lists': output})

# Get Specific List
@app.route('/list/<list_id>', methods=['GET'])
def get_list(list_id):

    list = List.query.filter_by(id=list_id).first()
    list_cards = Card.query.filter_by(list_id=list_id).all()

    list_data = {}
    list_data['title'] = list.title
    list_data['user_id'] = list.user_id

    output = []
    output = []
    for list_card in list_cards:
        list_card_data = {}
        list_card_data['list_id'] = list_card.list_id
        list_card_data['title'] = list_card.title
        list_card_data['description'] = list_card.description

        output.append(list_card_data)

    return jsonify({"List Data": list_data, "List Cards": output})

# Create List
@app.route('/list', methods=['POST'])
@token_required
def create_list(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})
    data = request.get_json()
    new_list = List(title=data['title'])
    db.session.add(new_list)
    db.session.commit()

    return jsonify({'message': 'New List Created!'})

@app.route('/list/<list_id>', methods=['PUT'])
@token_required
def update_list(current_user, list_id):
    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})
    data = request.get_json()
    list = List.query.filter_by(id=list_id).first()
    if list.user_id == current_user.id:
        list.title = data['title']
        db.session.commit()

        return jsonify({'message': 'List Update Successfully!'})
    else:
        return jsonify({'message': 'This list Does not belong to you!'})


@app.route('/list/<list_id>', methods=['DELETE'])
@token_required
def delete_list(current_user, list_id):
    list = List.query.filter_by(id=list_id).first()
    if list.user_id == current_user.id:
        db.session.delete(list)
        db.session.commit()

        return jsonify({'message': 'List Deleted Successfully!'})
    else:
        return jsonify({'message': 'This list Does not belong to you!'})

################################################
################ Cards ROUTES ##################
################################################
# GET ALL CARDS
@app.route('/cards', methods=['GET'])
@token_required
def get_all_cards(current_user):
    if current_user.admin:

        query = 'SELECT Count(*), Card.id, Card.title, Card.description FROM Card LEFT JOIN Comment on Card.id = Comment.card_id group by Comment.card_id  order by Count() DESC'
        rows = db.engine.execute(query)
        output = []

        for card in rows:
            card_data = {}
            card_data['id'] = card.id
            card_data['title'] = card.title
            card_data['description'] = card.description


            output.append(card_data)

        return jsonify({'Cards': output})
    else:
        query = 'SELECT Count(*), Card.id, Card.title, Card.description FROM Card WHERE Card.list_id = :current_user.id LEFT JOIN Comment on Card.id = Comment.card_id group by Comment.card_id  order by Count() DESC'
        rows = db.engine.execute(query)
        output = []

        for card in rows:
            card_data = {}
            card_data['id'] = card.id
            card_data['title'] = card.title
            card_data['description'] = card.description


            output.append(card_data)

        return jsonify({'Cards': output})

# Get Specific Card
@app.route('/cards/<card_id>', methods=['GET'])
@token_required
def get_one_card(current_user, card_id):
    card = Card.query.filter_by(id=card_id).first()
    card_first_three_comments = Comment.query.filter_by(card_id=card.id).limit(3).all()
    if not card:
        return jsonify({'message': 'No Card Found!'})

    card_data = {}
    card_data['id'] = card.id
    card_data['list_id'] = card.list_id
    card_data['title'] = card.title
    card_data['description'] = card.description

    output_comments = []
    for comment in card_first_three_comments:
        card_comment_data = {}
        card_comment_data['id'] = comment.id
        card_comment_data['content'] = comment.content
        output_comments.append(card_comment_data)

    return jsonify({'Card': card_data, 'Comments': output_comments})


# Create Card
@app.route('/cards', methods=['POST'])
@token_required
def create_card(current_user):
    data = request.get_json()

    if current_user.admin:
        new_card = Card(list_id=data['list_id'], title=data['title'], description=data['description'])
        db.session.add(new_card)
        db.session.commit()

        card_data = {}
        card_data['id'] = new_card.id
        card_data['list_id'] = new_card.list_id
        card_data['title'] = new_card.title
        card_data['description'] = new_card.description

        return jsonify({'message': 'New Card Created!', 'Card': card_data})
    else:
        current_user_lists = List.query.filter_by(user_id=current_user.id).all()
        if data['list_id'] in current_user_lists:
            new_card = Card(list_id=data['list_id'], title=data['title'], description=data['description'])
            db.session.add(new_card)
            db.session.commit()

            card_data = {}
            card_data['id'] = new_card.id
            card_data['list_id'] = new_card.list_id
            card_data['title'] = new_card.title
            card_data['description'] = new_card.description

            return jsonify({'message': 'New Card Created!', 'Card': card_data})
        else:
            return jsonify({'message': 'Can not add cart to this list'})


# Update Card
@app.route('/cards/<card_id>', methods=['PUT'])
@token_required
def promote_card(current_user, card_id):
    data = request.get_json()
    card = Card.query.filter_by(id=card_id).first()
    if not card:
        return jsonify({'message': 'No Card Found!'})

    card.list_id = data['list_id']
    card.title = data['title']
    card.description = data['description']

    db.session.commit()

    return jsonify({'message': 'Card Updated Successfully!'})


# Delete Card
@app.route('/cards/<card_id>', methods=['DELETE'])
@token_required
def delete_card(current_user, card_id):
    card = Card.query.filter_by(id=card_id).first()
    if not card:
        return jsonify({'message': 'No Card Found!'})

    db.session.delete(card)
    db.session.commit()

    return jsonify({'message': 'Card Has Been Deleted!'})


################################################
############## Comments ROUTES #################
################################################


# GET ALL Comments
@app.route('/comment', methods=['GET'])
@token_required
def get_all_comments(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})

    comments = Comment.query.all()
    output = []

    for comment in comments:
        comment_data = {}
        comment_data['user_id'] = comment.user_id
        comment_data['card_id'] = comment.card_id
        comment_data['content'] = comment.content

        output.append(comment_data)

    return jsonify({'Comments': output})


# Get Specific Comment
@app.route('/comment/<comment_id>', methods=['GET'])
# @token_required
def get_one_comment(comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()
    if not comment:
        return jsonify({'message': 'No Comment Found!'})

    comment_data = {}
    comment_data['id'] = comment.id
    comment_data['user_id'] = comment.user_id
    comment_data['card_id'] = comment.card_id
    comment_data['content'] = comment.content

    return jsonify({'Comment': comment_data})


# Create Comment
@app.route('/comment', methods=['POST'])
@token_required
def create_comment(current_user):
    data = request.get_json()
    new_comment = Comment(user_id=current_user.id, card_id=data['card_id'], content=data['content'])
    db.session.add(new_comment)
    db.session.commit()

    comment_data = {}
    comment_data['id'] = new_comment.id
    comment_data['user_id'] = new_comment.user_id
    comment_data['card_id'] = new_comment.card_id
    comment_data['content'] = new_comment.content

    return jsonify({'message': 'New Comment Created!', 'user': comment_data})


# Update Comment
@app.route('/comment/<comment_id>', methods=['PUT'])
@token_required
def promote_comment(current_user, comment_id):
    data = request.get_json()
    comment = Comment.query.filter_by(id=comment_id).first()
    if not comment:
        return jsonify({'message': 'No Comment Found!'})

    comment.content = data['content']
    db.session.commit()

    return jsonify({'message': 'Comment Updated!'})


# Delete Comment
@app.route('/comment/<comment_id>', methods=['DELETE'])
@token_required
def delete_comment(current_user, comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()
    if not comment:
        return jsonify({'message': 'No Comment Found!'})

    db.session.delete(comment)
    db.session.commit()

    return jsonify({'message': 'Comment Has Been Deleted!'})

################################################
############### Replies ROUTES #################
################################################

# GET Comment Replies
@app.route('/reply/<comment_id>', methods=['GET'])
@token_required
def get_all_replies(current_user, comment_id):
    if not current_user.admin:
        return jsonify({'message': 'You are not authorized'})

    replies = Reply.query.filter_by(comm_id=comment_id).all()
    output = []

    for reply in replies:
        reply_data = {}
        reply_data['user_id'] = reply.user_id
        reply_data['card_id'] = reply.card_id
        reply_data['comment_id'] = reply.comm_id
        reply_data['content'] = reply.content

        output.append(reply_data)

    return jsonify({'Comment Replies': output})

#
# # Get Specific Comment
# @app.route('/comment/<comment_id>', methods=['GET'])
# # @token_required
# def get_one_comment(comment_id):
#     comment = Comment.query.filter_by(id=comment_id).first()
#     if not comment:
#         return jsonify({'message': 'No Comment Found!'})
#
#     comment_data = {}
#     comment_data['id'] = comment.id
#     comment_data['user_id'] = comment.user_id
#     comment_data['card_id'] = comment.card_id
#     comment_data['content'] = comment.content
#
#     return jsonify({'Comment': comment_data})
#


# Create Reply
@app.route('/reply', methods=['POST'])
@token_required
def create_reply(current_user):
    data = request.get_json()
    new_reply = Reply(user_id=current_user.id, comm_id=data['comment_id'], card_id=data['card_id'], content=data['content'])

    db.session.add(new_reply)
    db.session.commit()

    reply_data = {}
    reply_data['id'] = new_reply.id
    reply_data['user_id'] = new_reply.user_id
    reply_data['card_id'] = new_reply.card_id
    reply_data['content'] = new_reply.content

    return jsonify({'message': 'New Reply Created!', 'user': reply_data})


# Update Reply
@app.route('/reply/<reply_id>', methods=['PUT'])
@token_required
def promote_reply(current_user, reply_id):
    data = request.get_json()
    reply = Reply.query.filter_by(id=reply_id).first()

    if not reply:
        return jsonify({'message': 'No Reply Found!'})

    reply.content = data['content']
    db.session.commit()

    return jsonify({'message': 'Reply Updated!'})


# Delete Reply
@app.route('/reply/<reply_id>', methods=['DELETE'])
@token_required
def delete_reply(current_user, reply_id):
    reply = Reply.query.filter_by(id=reply_id).first()
    if not reply:
        return jsonify({'message': 'No Reply Found!'})

    db.session.delete(reply)
    db.session.commit()

    return jsonify({'message': 'Reply Has Been Deleted!'})


if __name__ == '__main__':
    app.run(debug=True)


