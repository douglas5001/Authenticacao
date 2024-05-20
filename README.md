# Authenticacao


Bibliotecas

```jsx
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import JWTManager
from datetime import timedelta
```

model

```python
class UsuarioModel(db.Model):
    __tablename__ = 'usuario'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    nome = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    senha = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean)

    def encriptar_senha(self):
        self.senha = pbkdf2_sha256.hash(self.senha)

    def ver_senha(self, senha):
        return pbkdf2_sha256.verify(senha, self.senha)
```

Services

```python
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if claims['roles'] != 'admin':
            return make_response(jsonify(message='Náo é prermitido esse recurco, só para administradores'), 403)
        else:
            return fn(*args, **kwargs)
    return wrapper
```

Schema

```python
class LoginSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UsuarioModel
        load_instance = True
        fields = ("id", "nome", "email", "senha")
```

Views

```python
class LoginList(Resource):
    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        usuario_token = listar_usuario_id(identity)  #(identity)
        if usuario_token.is_admin:
            roles = 'admin'
        else:
            roles = 'user'

        return {'roles':roles}

    def post(self):
        ls = LoginSchema()
        validate = ls.validate(request.json)
        if validate:
            return make_response(jsonify(validate), 400)
        else:
            email = request.json["email"]
            senha = request.json["senha"]

            usuario_db = listar_usuario_email((email))

            if usuario_db and usuario_db.ver_senha(senha):
                access_token = create_access_token(
                    identity=usuario_db.id,
                    expires_delta=timedelta(seconds=500)
                )

                refresh_token = create_refresh_token(
                    identity=usuario_db.id
                )

                return make_response(jsonify({
                    'access_token':access_token,
                    'refresh_token':refresh_token,
                    'message':'login realizado com sucesso'
                }), 200)

            return make_response(jsonify({
                'message':'Credenciais estao invalidadas'
            }), 401)

class RefreshTokenList(Resource):
    @jwt_required(refresh=True)
    def post(self):
        usuario_token = get_jwt_identity()
        access_token = create_access_token(
            identity=usuario_token,
            expires_delta=timedelta(seconds=100)
        )
        refresh_token = create_refresh_token(
            identity=usuario_token
        )

        return make_response({
            'access_token':access_token,
            'refresh_token':refresh_token
        }, 200)
```

```python
api.add_resource(RefreshTokenList, '/token/refresh')
api.add_resource(LoginList, '/login')
```
