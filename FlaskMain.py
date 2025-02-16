from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileAllowed
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Создаем папку для хранения файлов, если её нет
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Инициализация базы данных
def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS classes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT UNIQUE NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS students (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            user_id INTEGER UNIQUE NOT NULL,
                            class_id INTEGER NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users (id),
                            FOREIGN KEY (class_id) REFERENCES classes (id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS achievements (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id INTEGER NOT NULL,
                            filename TEXT NOT NULL,
                            description TEXT NOT NULL,
                            FOREIGN KEY (student_id) REFERENCES students (id))''')
        conn.commit()

# Формы
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=999)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=999)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

class AchievementForm(FlaskForm):
    description = TextAreaField('Описание', validators=[DataRequired(), Length(max=500)])
    file = FileField('Фото', validators=[DataRequired(), FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField('Загрузить')

class ClassForm(FlaskForm):
    name = StringField('Название класса', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Создать класс')

class StudentForm(FlaskForm):
    name = StringField('Имя ученика', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Добавить ученика')

# Проверка аутентификации
@app.before_request
def check_authentication():
    if request.endpoint not in ['login', 'register'] and 'user' not in session:
        return redirect(url_for('login'))

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (form.username.data, form.password.data))
            conn.commit()
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (form.username.data, form.password.data))
            user = cursor.fetchone()
        if user:
            session['user'] = user[0]
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('choose_grade'))
        else:
            flash('Неправильный логин или пароль', 'danger')
    return render_template('loggin.html', form=form)

# Выход
@app.route ('/logout')
def logout():
    session.pop('user', None)
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

# Страница выбора класса
@app.route('/choose-grade', methods=['GET', 'POST'])
def choose_grade():
    form = ClassForm()
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM classes")
        classes = cursor.fetchall()
    if form.validate_on_submit():
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO classes (name) VALUES (?)", (form.name.data,))
            conn.commit()
        flash('Класс создан!', 'success')
        return redirect(url_for('choose_grade'))
    return render_template('add-grade.html', form=form, classes=classes)

# Страница выбора ученика
@app.route('/choose-person/<int:class_id>', methods=['GET', 'POST'])
def choose_person(class_id):
    form = StudentForm()
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM students WHERE class_id = ?", (class_id,))
        students = cursor.fetchall()
    if form.validate_on_submit():
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO students (name, user_id, class_id) VALUES (?, ?, ?)", (form.name.data, session['user'], class_id))
            conn.commit()
        flash('Ученик добавлен!', 'success')
        return redirect(url_for('choose_person', class_id=class_id))
    return render_template('add-person.html', form=form, students=students, class_id=class_id)

# Страница ученика
@app.route('/student/<int:student_id>', methods=['GET', 'POST'])
def student_page(student_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, user_id FROM students WHERE id = ?", (student_id,))
        student = cursor.fetchone()

    if not student:
        flash('Студент не найден', 'danger')
        return redirect(url_for('choose_grade'))

    is_owner = student[2] == session['user']  # Проверка, является ли текущий пользователь владельцем страницы

    achievement_form = AchievementForm()

    if achievement_form.validate_on_submit():
        # Обработка загрузки достижения
        filename = secure_filename(achievement_form.file.data.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        achievement_form.file.data.save(file_path)

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO achievements (student_id, filename, description) VALUES (?, ?, ?)",
                           (student_id, filename, achievement_form.description.data))
            conn.commit()
        flash('Достижение добавлено!', 'success')
        return redirect(url_for('student_page', student_id=student_id))

    # Загружаем достижения для студента
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT filename, description FROM achievements WHERE student_id = ?", (student_id,))
        achievements = cursor.fetchall()

    return render_template('student_page.html', student=student, is_owner=is_owner,
                           form=achievement_form, achievements=achievements)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=81)
