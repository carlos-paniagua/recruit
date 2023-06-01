from flask import Flask, jsonify, request
import base64

app = Flask(__name__)

# ユーザーデータ格納場所
users = []

#テスト用ユーザーデータ
users.append({
    'user_id': 'TaroYamada',
    'password': 'PaSSwd4TY',
    'nickname': 'たろー',
    'comment': '僕は元気です'
})

#アカウントを新規作成
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')

    #失敗：必須項目の存在チェック
    if not user_id or not password:
        return jsonify(
            {
                'message': 'Account creation failed', 
                'cause': 'required user_id and password'
            }), 400

    #値の長さチェック
    #失敗：user_idが6文字以上20文字以内か確認
    if len(user_id) < 6 or len(user_id) > 20:
        return jsonify(
            {
                'message': 'Account creation failed', 
                'cause': 'required user_id and password'
            }), 400

    #失敗：passwordが8文字以上20文字以内か確認
    if len(password) < 8 or len(password) > 20:
        return jsonify(
            {
                'message': 'Account creation failed',
                'cause': 'required user_id and password'
            }), 400

    #文字種のチェック
    #失敗：半角英数字記号確認
    if not all(c.isalnum() or c in '!@#$%^&*()-_=+{}[]|:;<>,.?/~`' for c in password):
        return jsonify(
            {
                'message': 'Account creation failed',
                'cause': 'required user_id and password'
            }), 400
        
    #失敗：既に同じuser_idを持つアカウントが存在している場合
    if user_id == users['user_id']:
        return jsonify(
            {
                "message": "Account creation failed",
                "cause": "already same user_id is used"
            }), 400
        
    # ユーザーアカウントの作成
    user = {
        'user_id': user_id,
        'password': password
    }

    users.append(user)

    #成功：200
    return jsonify(
        {
            'message': 'Account successfully created',
            'user': user
        }), 200

#指定user_idのユーザー情報を返す
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    
    #失敗:Authorizationヘッダーでの認証が失敗した場合:401
    auth_header = request.headers.get('Authorization')
    if not auth_header or not validate_auth_header(auth_header, user_id):
        return jsonify(
            {
                'message': 'Authentication Failed'
            }), 401

    # ユーザ情報の検索
    user = find_user_by_id(user_id)

    #失敗:指定user_idのユーザー情報が存在しない場合:404
    if not user:
        return jsonify(
            {
                'message': 'No User found'
            }), 404
        
    #成功：200
    return jsonify(
        {
            'message': 'User details by user_id', 
            'user': user
        }), 200

#指定idのユーザ情報を更新し，更新したユーザ情報を返す
@app.route('/users/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    
    #失敗:Authorizationヘッダーでの認証が失敗した場合:401
    auth_header = request.headers.get('Authorization')
    if not auth_header or not validate_auth_header(auth_header, user_id):
        return jsonify(
            {
                'message': 'Authentication Failed'
            }), 401

    # ユーザ情報の検索
    user = find_user_by_id(user_id)
    
    #失敗:指定user_idのユーザ情報が存在しない場合:404 
    if not user:
        return jsonify(
            {
                'message': 'No User found'
            }), 404
        
    #失敗:認証と異なるIDのユーザを指定した場合:403
    auth_user_id = get_user_id_from_auth_header(auth_header)
    if user['user_id'] != auth_user_id:
        return jsonify(
            {
                'message': 'No Permission for Update'
            }), 403

    #失敗：user_idやpasswordを変更しようとしている場合:400
    if 'user_id' in request.json or 'password' in request.json:
        return jsonify(
            {
                'message': 'User updation failed', 
                'cause': 'not updatable user_id and password'
            }), 400

    # ユーザ情報の更新
    nickname = request.json.get('nickname')
    comment = request.json.get('comment')

    #失敗:nicknameとcommentが両方とも指定されていない場合:400
    if not nickname and not comment:
        return jsonify(
            {
                'message': 'User updation failed',
                'cause': 'required nickname or comment'
            }), 400
        
    #nickname任意30文字以内制御コード以外の任意の文字
    if nickname is not None:
        if nickname == "":
            user["nickname"] = user_id  # 空文字の場合は初期値（ユーザID）に戻る
        elif len(nickname) <= 30 and not contains_characters(nickname):
            user["nickname"] = nickname
        else:
            return jsonify({
                "message": "User updation failed",
                "cause": "invalid nickname"
            }), 400
            
    # comment任意100文字以内制御コード以外の任意の文字      
    if comment is not None:
        if comment == "":
            user["comment"] = None  # 空文字の場合はクリアされる
        elif len(comment) <= 100 and not contains_characters(comment):
            user["comment"] = comment
        else:
            return jsonify({
                "message": "User updation failed",
                "cause": "invalid comment"
            }), 400

    #成功:200
    return jsonify(
        {
            'message': 'User successfully updated', 
            'user': user
        }), 200

#アカウントを削除
@app.route('/close', methods=['POST'])
def close_account():
    
    #失敗:Authorizationヘッダーでの認証が失敗した場合:401
    auth_header = request.headers.get('Authorization')
    if not auth_header or not validate_auth_header(auth_header,user_id):
        return jsonify(
            {
                'message': 'Authentication Failed'
            }), 401

    # ユーザIDの取得
    user_id = get_user_id_from_auth_header(auth_header)

    # ユーザ情報の削除
    user = find_user_by_id(user_id)
    if user:
        users.remove(user)

    #成功:200
    return jsonify(
        {
            'message': 'Account and user successfully closed'
        }), 200

def validate_auth_header(auth_header, user_id):
    # Authorizationヘッダーの解析
    auth_type, encoded_credential = auth_header.split(' ')
    credential = base64.b64decode(encoded_credential).decode('utf-8')
    auth_user_id, auth_password = credential.split(':')

    # ユーザIDとパスワードの一致をチェック
    return auth_user_id == user_id and auth_password == get_password_by_user_id(user_id)

def get_user_id_from_auth_header(auth_header):
    # AuthorizationヘッダーからユーザIDを取得
    auth_type, encoded_credential = auth_header.split(' ')
    credential = base64.b64decode(encoded_credential).decode('utf-8')
    user_id, _ = credential.split(':')
    return user_id

def find_user_by_id(user_id):
    # ユーザIDでユーザ情報を検索
    for user in users:
        if user['user_id'] == user_id:
            return user

    return None

def get_password_by_user_id(user_id):
    # ユーザIDに対応するパスワードを取得
    user = find_user_by_id(user_id)
    if user:
        return user['password']

    return None

def contains_characters(string):
    
    control_characters = [chr(i) for i in range(32)]  # ASCIIコードの0〜31が制御文字
    for char in string:
        if char in control_characters:
            return True
    return False
if __name__ == '__main__':
    app.run()
