import sys
try:
    from flask import Flask, render_template, request, redirect, url_for, flash, abort
    from flask_sqlalchemy import SQLAlchemy
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    from datetime import datetime
    from sqlalchemy import text
    import os
    import json
except ImportError as e:
    missing = str(e).split()[-1]
    print("Erro de importação:", e)
    print("Instale as dependências executando 'pip install -r requirements.txt' no ambiente correto.")
    sys.exit(1)

# helper for allowed image extensions
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}
PDF_EXTENSIONS = {'pdf'}

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///manga.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'change-this-secret'  # para sessões e flash messages

# upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# make datetime available in templates
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Manga(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    capa = db.Column(db.String(1), nullable=True)  # legacy single cover (kept for compatibility)
    image_filename = db.Column(db.String(300), nullable=True)  # legacy single cover (kept for compatibility)
    image_filenames = db.Column(db.Text, nullable=True)  # JSON list of uploaded JPGs in user order
    pdf_filename = db.Column(db.String(300), nullable=True)    # optional PDF with full images
    posted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Manga {self.title}>"

# association table for favorites
user_favorites = db.Table(
    'user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('manga_id', db.Integer, db.ForeignKey('manga.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_scanner = db.Column(db.Boolean, default=False)
    favorites = db.relationship('Manga', secondary=user_favorites, backref='fans')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def add_favorite(self, manga):
        if manga not in self.favorites:
            self.favorites.append(manga)
            db.session.commit()

    def remove_favorite(self, manga):
        if manga in self.favorites:
            self.favorites.remove(manga)
            db.session.commit()

    def is_favorite(self, manga):
        return manga in self.favorites

    def __repr__(self):
        return f"<User {self.username}>"

@app.route('/')
def index():
    mangas = Manga.query.order_by(Manga.posted_at.desc()).all()
    # convert filenames JSON to list for template convenience
    for m in mangas:
        if m.image_filenames:
            try:
                parsed = json.loads(m.image_filenames)
                # ensure it's a list
                if isinstance(parsed, str):
                    m._imgs = [parsed]
                elif isinstance(parsed, list):
                    m._imgs = parsed
                else:
                    m._imgs = []
            except Exception:
                m._imgs = []
        else:
            m._imgs = [m.image_filename] if m.image_filename else []
    return render_template('index.html', mangas=mangas)

@app.route('/manga/<int:manga_id>')
def manga_detail(manga_id):
    manga = Manga.query.get_or_404(manga_id)
    if manga.image_filenames:
        try:
            parsed = json.loads(manga.image_filenames)
            if isinstance(parsed, str):
                manga._imgs = [parsed]
            elif isinstance(parsed, list):
                manga._imgs = parsed
            else:
                manga._imgs = []
        except Exception:
            manga._imgs = []
    else:
        manga._imgs = [manga.image_filename] if manga.image_filename else []
    return render_template('detail.html', manga=manga)

def admin_required(func):
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    decorated_view.__name__ = func.__name__
    return decorated_view

def scanner_or_admin_required(func):
    @login_required
    def decorated_view(*args, **kwargs):
        if not (current_user.is_scanner or current_user.is_admin):
            abort(403)
        return func(*args, **kwargs)
    decorated_view.__name__ = func.__name__
    return decorated_view

@app.route('/add', methods=['GET', 'POST'])
@scanner_or_admin_required
def add_manga():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        description = request.form.get('description')
        # handle multiple images
        filenames = []
        files = request.files.getlist('images')
        if files:
            files = [f for f in files if f and f.filename]
            if len(files) > 320:
                flash('O máximo são 320 imagens.', 'danger')
                return redirect(url_for('add_manga'))
            for f in files:
                if allowed_file(f.filename, IMAGE_EXTENSIONS):
                    fname = secure_filename(f.filename)
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                    f.save(dest)
                    filenames.append(fname)
                else:
                    flash('Apenas arquivos de imagem (JPG/PNG/GIF) são permitidos na galeria.', 'danger')
                    return redirect(url_for('add_manga'))
        # keep legacy single cover
        filename = filenames[0] if filenames else None
        # handle pdf file (only translators or admins can upload)
        pdf_file = request.files.get('pdf')
        pdfname = None
        if pdf_file and pdf_file.filename != '':
            if not current_user.is_scanner and not current_user.is_admin:
                flash('Somente administradores/scanners podem enviar um PDF.', 'danger')
                return redirect(url_for('add_manga'))
            if allowed_file(pdf_file.filename, PDF_EXTENSIONS):
                pdfname = secure_filename(pdf_file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], pdfname)
                pdf_file.save(save_path)
            else:
                flash('Apenas PDFs são permitidos.', 'danger')
                return redirect(url_for('add_manga'))

        if not title:
            flash("O título é obrigatório.", "danger")
            return redirect(url_for('add_manga'))
        new_manga = Manga(
            title=title,
            author=author,
            description=description,
            image_filename=filename,
            image_filenames=json.dumps(filenames) if filenames else None,
            pdf_filename=pdfname
        )
        db.session.add(new_manga)
        db.session.commit()
        flash("Mangá postado com sucesso!", "success")
        return redirect(url_for('index'))
    return render_template('add.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        # role flags removed from registration form; accounts are regular users by default
        if not username or not password:
            flash('Usuário e senha são obrigatórios.', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Conta criada com sucesso e você foi conectado.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login bem-sucedido.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Credenciais inválidas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>/edit-role', methods=['POST'])
@admin_required
def admin_edit_user_role(user_id):
    user = User.query.get_or_404(user_id)
    # impedir que alguém remova as permissões do único admin
    if user.is_admin and not User.query.filter_by(is_admin=True).count() > 1:
        flash('Não é possível remover as permissões do único administrador.', 'danger')
        return redirect(url_for('admin_users'))
    # impedir que um utilizador remova as suas próprias permissões de admin
    if user.id == current_user.id and request.form.get('is_admin') != 'on':
        flash('Não é possível remover as suas próprias permissões de administrador.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = request.form.get('is_admin') == 'on'
    user.is_scanner = request.form.get('is_scanner') == 'on'
    db.session.commit()
    flash(f'Permissões do utilizador "{user.username}" atualizadas com sucesso.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/favorite/<int:manga_id>', methods=['POST'])
@login_required
def toggle_favorite(manga_id):
    manga = Manga.query.get_or_404(manga_id)
    if current_user.is_favorite(manga):
        current_user.remove_favorite(manga)
        flash('Removido dos favoritos.', 'info')
    else:
        current_user.add_favorite(manga)
        flash('Adicionado aos favoritos.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/favorites')
@login_required
def view_favorites():
    return render_template('favorites.html', mangas=current_user.favorites)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.route('/edit/<int:manga_id>', methods=['GET', 'POST'])
@admin_required
def edit_manga(manga_id):
    manga = Manga.query.get_or_404(manga_id)
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        description = request.form.get('description')
        if not title:
            flash('O título é obrigatório.', 'danger')
            return redirect(url_for('edit_manga', manga_id=manga_id))
        manga.title = title
        manga.author = author
        manga.description = description
        db.session.commit()
        flash('Mangá atualizado com sucesso.', 'success')
        return redirect(url_for('manga_detail', manga_id=manga_id))
    return render_template('edit.html', manga=manga)

@app.route('/delete/<int:manga_id>', methods=['POST'])
@admin_required
def delete_manga(manga_id):
    manga = Manga.query.get_or_404(manga_id)
    # remove image file from disk if present
    if manga.image_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], manga.image_filename))
        except OSError:
            pass
    db.session.delete(manga)
    db.session.commit()
    flash('Mangá excluído com sucesso.', 'success')
    return redirect(url_for('index'))

def ensure_admin():
    # cria usuário administrador padrão se não existir
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('aZ7!qL9@vT2#rX8$kM4^p')  # altere depois para um valor seguro
        db.session.add(admin)
        db.session.commit()
        print('Usuário administrador criado: admin/admin')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # migrar esquema: adiciona campo image_filename em instalações antigas
        # somente se a coluna não existir já
        insp = db.session.execute(text("PRAGMA table_info(manga)"))
        columns = [row[1] for row in insp]
        if 'image_filename' not in columns:
            try:
                db.session.execute(text('ALTER TABLE manga ADD COLUMN image_filename VARCHAR(300)'))
                db.session.commit()
            except Exception:
                db.session.rollback()
        if 'image_filenames' not in columns:
            try:
                db.session.execute(text('ALTER TABLE manga ADD COLUMN image_filenames TEXT'))
                db.session.commit()
            except Exception:
                db.session.rollback()
        if 'pdf_filename' not in columns:
            try:
                db.session.execute(text('ALTER TABLE manga ADD COLUMN pdf_filename VARCHAR(300)'))
                db.session.commit()
            except Exception:
                db.session.rollback()
    # user table migration
        user_cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(user)"))]
        # note: 'is_translator' role removed from schema; only 'is_scanner' remains
        if 'is_scanner' not in user_cols:
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN is_scanner BOOLEAN DEFAULT 0'))
                db.session.commit()
            except Exception:
                db.session.rollback()
        # ensure existing manga rows have list rather than string
        try:
            for m in Manga.query.all():
                if m.image_filenames:
                    try:
                        parsed = json.loads(m.image_filenames)
                        if isinstance(parsed, str):
                            m.image_filenames = json.dumps([parsed])
                            db.session.add(m)
                    except Exception:
                        # if it's not valid json, wrap as list
                        m.image_filenames = json.dumps([m.image_filenames])
                        db.session.add(m)
            db.session.commit()
        except Exception:
            db.session.rollback()
        ensure_admin()
        # se ainda não houver mangás, cria alguns exemplos usando as imagens de placeholder
        if Manga.query.count() == 0:
            sample_images = ["anime1.png", "anime2.png", "anime3.png"]
            for idx, fname in enumerate(sample_images, start=1):
                db.session.add(Manga(
                    title=f"Exemplo {idx}",
                    author="Autor Exemplo",
                    description="Descrição de exemplo com arte de anime.",
                    image_filenames=json.dumps([fname])
                ))
            db.session.commit()
        # Executar em modo de produção simples (sem debug) para não exibir informações internas.
    app.run(debug=True)
