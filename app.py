import csv
import io
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, make_response, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "instance" / "enfermeria.sqlite3"

def create_app(test_config=None):
    app = Flask(__name__, instance_path=str(BASE_DIR / "instance"), instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),
        DATABASE=os.environ.get("ENFERMERIA_DATABASE", str(DEFAULT_DB)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "0") == "1",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        # Suitable only for local development; configure FLASK_SECRET_KEY before deployment.
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning("FLASK_SECRET_KEY no configurada; las sesiones se invalidarán al reiniciar.")
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA busy_timeout = 10000")
        return g.db

    app.get_db = get_db

    @app.teardown_appcontext
    def close_db(error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'enfermeria' CHECK(role IN ('admin','enfermeria')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id TEXT UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            course TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_students_name ON students(last_name, first_name);
        CREATE INDEX IF NOT EXISTS idx_students_course ON students(course);
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL REFERENCES students(id),
            created_at TEXT NOT NULL,
            arrived_at TEXT NOT NULL,
            departed_at TEXT,
            reason TEXT NOT NULL,
            symptoms TEXT NOT NULL DEFAULT '',
            actions_taken TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'espera' CHECK(status IN ('espera','atencion','finalizada')),
            created_by INTEGER NOT NULL REFERENCES users(id),
            updated_at TEXT NOT NULL,
            updated_by INTEGER NOT NULL REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_visits_status_date ON visits(status, arrived_at);
        CREATE INDEX IF NOT EXISTS idx_visits_student_date ON visits(student_id, arrived_at);
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id INTEGER,
            happened_at TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        """)
        db.commit()

    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_urlsafe(32)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def security_and_setup():
        init_db()
        if request.method == "POST":
            sent = request.form.get("_csrf_token", "")
            expected = session.get("_csrf_token", "")
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(400, description="Token de formulario inválido. Recarga la página e inténtalo de nuevo.")

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def current_user():
        if not session.get("user_id"):
            return None
        return get_db().execute("SELECT id, username, role FROM users WHERE id=? AND active=1",
                                (session["user_id"],)).fetchone()

    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    def audit(action, entity, entity_id=None, detail=""):
        user = current_user()
        get_db().execute(
            "INSERT INTO audit_log(user_id, action, entity, entity_id, happened_at, detail) VALUES(?,?,?,?,?,?)",
            (user["id"] if user else None, action, entity, entity_id,
             datetime.now().astimezone().isoformat(timespec="seconds"), detail[:500])
        )

    def now_iso():
        return datetime.now().astimezone().isoformat(timespec="minutes")

    def parse_dt(value):
        try:
            return datetime.fromisoformat(value).astimezone().isoformat(timespec="minutes")
        except (ValueError, TypeError):
            return None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT * FROM users WHERE username=? AND active=1", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["_csrf_token"] = secrets.token_urlsafe(32)
                audit("inicio_sesion", "user", user["id"])
                get_db().commit()
                return redirect(url_for("dashboard"))
            flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit("cierre_sesion", "user", session.get("user_id"))
        get_db().commit()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        db = get_db()
        today = datetime.now().astimezone().date().isoformat()
        counts = {
            "espera": db.execute("SELECT COUNT(*) FROM visits WHERE status='espera' AND substr(arrived_at,1,10)=?", (today,)).fetchone()[0],
            "atencion": db.execute("SELECT COUNT(*) FROM visits WHERE status='atencion' AND substr(arrived_at,1,10)=?", (today,)).fetchone()[0],
            "finalizadas": db.execute("SELECT COUNT(*) FROM visits WHERE status='finalizada' AND substr(arrived_at,1,10)=?", (today,)).fetchone()[0],
            "total": db.execute("SELECT COUNT(*) FROM visits WHERE substr(arrived_at,1,10)=?", (today,)).fetchone()[0],
        }
        queue = db.execute("""SELECT v.*, s.first_name, s.last_name, s.course
            FROM visits v JOIN students s ON s.id=v.student_id
            WHERE v.status IN ('espera','atencion')
            ORDER BY CASE v.status WHEN 'atencion' THEN 0 ELSE 1 END, v.arrived_at""").fetchall()
        return render_template("dashboard.html", counts=counts, queue=queue)

    @app.route("/alumnos", methods=["GET", "POST"])
    @login_required
    def students():
        db = get_db()
        if request.method == "POST":
            first = request.form.get("first_name", "").strip()
            last = request.form.get("last_name", "").strip()
            course = request.form.get("course", "").strip()
            school_id = request.form.get("school_id", "").strip() or None
            if not first or not last or not course:
                flash("Nombre, apellido y curso son obligatorios.", "error")
            else:
                try:
                    cur = db.execute("INSERT INTO students(school_id,first_name,last_name,course) VALUES(?,?,?,?)",
                                     (school_id, first[:80], last[:80], course[:40]))
                    audit("crear", "student", cur.lastrowid, f"Curso: {course}")
                    db.commit()
                    flash("Alumno registrado.", "success")
                    return redirect(url_for("students"))
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash("Ese identificador escolar ya está registrado.", "error")
        q = request.args.get("q", "").strip()
        if q:
            like = f"%{q}%"
            rows = db.execute("""SELECT * FROM students WHERE active=1 AND
                (first_name LIKE ? OR last_name LIKE ? OR course LIKE ? OR school_id LIKE ?)
                ORDER BY last_name, first_name LIMIT 200""", (like, like, like, like)).fetchall()
        else:
            rows = db.execute("SELECT * FROM students WHERE active=1 ORDER BY last_name,first_name LIMIT 200").fetchall()
        return render_template("students.html", students=rows, q=q)

    @app.route("/atenciones/nueva", methods=["GET", "POST"])
    @login_required
    def new_visit():
        db = get_db()
        if request.method == "POST":
            student_id = request.form.get("student_id", type=int)
            reason = request.form.get("reason", "").strip()
            student = db.execute("SELECT * FROM students WHERE id=? AND active=1", (student_id,)).fetchone()
            if not student or not reason:
                flash("Selecciona un alumno válido e indica el motivo de consulta.", "error")
            else:
                arrived = parse_dt(request.form.get("arrived_at")) or now_iso()
                user = current_user()
                cur = db.execute("""INSERT INTO visits
                    (student_id,created_at,arrived_at,reason,symptoms,actions_taken,outcome,notes,status,created_by,updated_at,updated_by)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (student_id, now_iso(), arrived, reason[:200],
                     request.form.get("symptoms","").strip()[:2000],
                     request.form.get("actions_taken","").strip()[:2000],
                     request.form.get("outcome","").strip()[:1000],
                     request.form.get("notes","").strip()[:2000],
                     "espera", user["id"], now_iso(), user["id"]))
                audit("crear", "visit", cur.lastrowid, f"Motivo: {reason[:100]}")
                db.commit()
                flash("Atención registrada y añadida a la cola.", "success")
                return redirect(url_for("visit_detail", visit_id=cur.lastrowid))
        q = request.args.get("q", "").strip()
        if q:
            like = f"%{q}%"
            students_list = db.execute("""SELECT * FROM students WHERE active=1 AND
                (first_name LIKE ? OR last_name LIKE ? OR course LIKE ? OR school_id LIKE ?)
                ORDER BY last_name,first_name LIMIT 50""", (like,like,like,like)).fetchall()
        else:
            students_list = db.execute("SELECT * FROM students WHERE active=1 ORDER BY last_name,first_name LIMIT 50").fetchall()
        return render_template("visit_form.html", students=students_list, q=q, now=now_iso())

    def visit_or_404(visit_id):
        row = get_db().execute("""SELECT v.*, s.first_name,s.last_name,s.course,s.school_id,
            u.username AS nurse_username FROM visits v JOIN students s ON s.id=v.student_id
            JOIN users u ON u.id=v.created_by WHERE v.id=?""", (visit_id,)).fetchone()
        if not row:
            abort(404)
        return row

    @app.route("/atenciones/<int:visit_id>", methods=["GET", "POST"])
    @login_required
    def visit_detail(visit_id):
        db = get_db()
        visit = visit_or_404(visit_id)
        if request.method == "POST":
            action = request.form.get("action")
            user = current_user()
            if action == "iniciar" and visit["status"] == "espera":
                db.execute("UPDATE visits SET status='atencion',updated_at=?,updated_by=? WHERE id=?",
                           (now_iso(),user["id"],visit_id))
                audit("iniciar_atencion","visit",visit_id)
                db.commit()
                flash("Atención iniciada.", "success")
            elif action == "finalizar" and visit["status"] != "finalizada":
                db.execute("""UPDATE visits SET status='finalizada',departed_at=?,updated_at=?,updated_by=?,
                    symptoms=?,actions_taken=?,outcome=?,notes=? WHERE id=?""",
                    (now_iso(),now_iso(),user["id"],
                     request.form.get("symptoms","").strip()[:2000],
                     request.form.get("actions_taken","").strip()[:2000],
                     request.form.get("outcome","").strip()[:1000],
                     request.form.get("notes","").strip()[:2000],visit_id))
                audit("finalizar","visit",visit_id)
                db.commit()
                flash("Atención finalizada.", "success")
            elif action == "guardar" and visit["status"] != "finalizada":
                db.execute("""UPDATE visits SET symptoms=?,actions_taken=?,outcome=?,notes=?,updated_at=?,updated_by=? WHERE id=?""",
                    (request.form.get("symptoms","").strip()[:2000],
                     request.form.get("actions_taken","").strip()[:2000],
                     request.form.get("outcome","").strip()[:1000],
                     request.form.get("notes","").strip()[:2000],
                     now_iso(),user["id"],visit_id))
                audit("editar","visit",visit_id)
                db.commit()
                flash("Cambios guardados.", "success")
            else:
                flash("La acción no es válida para el estado actual.", "error")
            return redirect(url_for("visit_detail", visit_id=visit_id))
        return render_template("visit_detail.html", visit=visit_or_404(visit_id))

    @app.route("/atenciones")
    @login_required
    def visit_history():
        q = request.args.get("q", "").strip()
        db = get_db()
        if q:
            like = f"%{q}%"
            visits = db.execute("""SELECT v.*,s.first_name,s.last_name,s.course FROM visits v
                JOIN students s ON s.id=v.student_id
                WHERE s.first_name LIKE ? OR s.last_name LIKE ? OR s.course LIKE ? OR v.reason LIKE ?
                ORDER BY v.arrived_at DESC LIMIT 300""",(like,like,like,like)).fetchall()
        else:
            visits = db.execute("""SELECT v.*,s.first_name,s.last_name,s.course FROM visits v
                JOIN students s ON s.id=v.student_id ORDER BY v.arrived_at DESC LIMIT 200""").fetchall()
        return render_template("history.html", visits=visits, q=q)

    @app.route("/atenciones/<int:visit_id>/constancia/<tipo>")
    @login_required
    def receipt(visit_id, tipo):
        if tipo not in ("alumno", "profesor"):
            abort(404)
        visit = visit_or_404(visit_id)
        return render_template("receipt.html", visit=visit, tipo=tipo, printed_at=now_iso())

    @app.route("/exportar/alumnos.csv")
    @login_required
    def export_students():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["identificador_escolar", "nombre", "apellido", "curso", "activo"])
        for s in get_db().execute("SELECT school_id,first_name,last_name,course,active FROM students ORDER BY last_name,first_name"):
            writer.writerow([s["school_id"] or "", s["first_name"], s["last_name"], s["course"], s["active"]])
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = 'attachment; filename="alumnos_enfermeria.csv"'
        audit("exportar", "students")
        get_db().commit()
        return response

    @app.route("/importar/alumnos", methods=["GET", "POST"])
    @login_required
    def import_students():
        if request.method == "POST":
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename.lower().endswith(".csv"):
                flash("Selecciona un archivo CSV.", "error")
                return redirect(url_for("import_students"))
            try:
                text = uploaded.stream.read().decode("utf-8-sig")
                reader = csv.DictReader(io.StringIO(text))
                required = {"nombre", "apellido", "curso"}
                if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                    raise ValueError("El CSV debe incluir las columnas nombre, apellido y curso.")
                db = get_db()
                created = 0
                for row in reader:
                    first = (row.get("nombre") or "").strip()
                    last = (row.get("apellido") or "").strip()
                    course = (row.get("curso") or "").strip()
                    school_id = (row.get("identificador_escolar") or "").strip() or None
                    if not first or not last or not course:
                        continue
                    try:
                        cur = db.execute("INSERT INTO students(school_id,first_name,last_name,course) VALUES(?,?,?,?)",
                            (school_id,first[:80],last[:80],course[:40]))
                        created += 1
                        audit("importar","student",cur.lastrowid,"Importación CSV")
                    except sqlite3.IntegrityError:
                        continue
                db.commit()
                flash(f"Importación terminada: {created} alumno(s) nuevos. Los duplicados o filas incompletas se omitieron.", "success")
                return redirect(url_for("students"))
            except (UnicodeDecodeError, csv.Error, ValueError) as exc:
                flash(f"No se pudo importar el CSV: {exc}", "error")
        return render_template("import.html")

    @app.route("/admin/crear-usuario", methods=["GET", "POST"])
    @login_required
    def create_user():
        user = current_user()
        if user["role"] != "admin":
            abort(403)
        if request.method == "POST":
            username = request.form.get("username","").strip().lower()
            password = request.form.get("password","")
            role = request.form.get("role","enfermeria")
            if len(username) < 3 or len(password) < 12 or role not in ("admin","enfermeria"):
                flash("Usuario: mínimo 3 caracteres; contraseña: mínimo 12; selecciona un rol válido.", "error")
            else:
                try:
                    cur = get_db().execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                        (username,generate_password_hash(password),role))
                    audit("crear","user",cur.lastrowid,f"Rol: {role}")
                    get_db().commit()
                    flash("Usuario creado.", "success")
                    return redirect(url_for("dashboard"))
                except sqlite3.IntegrityError:
                    get_db().rollback()
                    flash("Ese nombre de usuario ya existe.", "error")
        return render_template("create_user.html")

    @app.cli.command("crear-admin")
    def create_admin_command():
        """Crear primer administrador: flask --app app crear-admin"""
        import getpass
        username = input("Usuario administrador: ").strip().lower()
        password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
        if len(username) < 3 or len(password) < 12:
            raise SystemExit("Usuario o contraseña demasiado cortos.")
        with app.app_context():
            init_db()
            db = get_db()
            try:
                db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                           (username,generate_password_hash(password),"admin"))
                db.commit()
            except sqlite3.IntegrityError:
                raise SystemExit("Ese usuario ya existe.")
        print("Administrador creado.")

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "Solicitud inválida.")), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("error.html", code=403, message="No tienes permiso para realizar esta acción."), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="No encontramos ese registro."), 404

    return app

app = create_app()

if __name__ == "__main__":
    # LAN access. Use Waitress (README) rather than Flask's dev server in real deployment.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
