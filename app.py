from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "uma_chave_secreta_aqui"  # importante para sessão

# 🔹 Conexão com MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",          # altere se não for root
    password="NovaSenhaAqui", # sua senha do MySQL
    database="sistema"
)
cursor = db.cursor(dictionary=True)

# 🔹 Decorator para proteger rotas privadas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# 🔹 Página inicial
@app.route("/")
def index():
    if "user" in session:
        return render_template("index.html", mensagem=f"Olá, {session['user']}! Você está logado.")
    return render_template("index.html")

# 🔹 Cadastro de usuário
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form["nome"]
        email = request.form["email"]
        senha = request.form["senha"].encode("utf-8")

        # Criptografar senha
        senha_hash = bcrypt.hashpw(senha, bcrypt.gensalt())

        try:
            sql = "INSERT INTO usuarios (nome, email, senha) VALUES (%s, %s, %s)"
            cursor.execute(sql, (nome, email, senha_hash))
            db.commit()
            return render_template("index.html", mensagem="Cadastro realizado com sucesso ✅")
        except mysql.connector.Error as err:
            return render_template("cadastro.html", mensagem=f"Erro ao cadastrar usuário: {err}")

    return render_template("cadastro.html")

# 🔹 Login de usuário
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"].encode("utf-8")

        sql = "SELECT * FROM usuarios WHERE email = %s"
        cursor.execute(sql, (email,))
        user = cursor.fetchone()

        if user:
            stored_hash = user["senha"]
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode("utf-8")

            if bcrypt.checkpw(senha, stored_hash):
                session["user"] = user["nome"]
                return redirect(url_for("dashboard"))

        return render_template("login.html", mensagem="Email ou senha incorretos ❌")

    return render_template("login.html")

# 🔹 Dashboard privado
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])

# 🔹 Alterar senha
@app.route("/alterar_senha", methods=["GET", "POST"])
@login_required
def alterar_senha():
    if request.method == "POST":
        senha_atual = request.form["senha_atual"].encode("utf-8")
        nova_senha = request.form["nova_senha"].encode("utf-8")

        sql = "SELECT * FROM usuarios WHERE nome = %s"
        cursor.execute(sql, (session["user"],))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(senha_atual, user["senha"].encode("utf-8")):
            nova_hash = bcrypt.hashpw(nova_senha, bcrypt.gensalt())
            cursor.execute("UPDATE usuarios SET senha=%s WHERE nome=%s", (nova_hash, session["user"]))
            db.commit()
            return render_template("dashboard.html", user=session["user"], mensagem="Senha alterada com sucesso ✅")
        else:
            return render_template("alterar_senha.html", mensagem="Senha atual incorreta ❌")

    return render_template("alterar_senha.html")

# 🔹 Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# 🔹 Rodar o app
if __name__ == "__main__":
    app.run(debug=True)
