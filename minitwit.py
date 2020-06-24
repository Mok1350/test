# -*- coding: utf-8 -*-

from __future__ import with_statement
import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from contextlib import closing
from flask import Flask,request,session,url_for,redirect,render_template,abort,g,flash
from werkzeug.security import check_password_hash, generate_password_hash

a = None
b = None
c = None
cal = None

DATABASE = 'minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS',silent=True)

# 데이터베이스

#데이터베이스와 연결
def connect_db():
    """Return a new connection to the database."""
    return sqlite3.connect(app.config['DATABASE'])

#데이터베이스 연결 및 사용자 정보에 관한 요청 처리
@app.before_request
def before_request():
    """Make sure we are connected to the database each request and Look
    up the current user so that we know he's there.
    """
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']],one=True)

#데이터베이스 연결 종료를 처리
@app.teardown_request
def teardown_request(exception):
    """Close the database again at the end of the reqyest."""
    if hasattr(g,'db'):
        g.db.close()

#query함수는 질의문, 질의문에 들어가는 인자,
#결과값의 일부를 받을지 전체를 받을지 결정하는 boolean값으로 이루어져 있다.
def query_db(query, args=(),  one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx,value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

#데이터베이스 업데이트 함수(내용 삭제 의미가 아님)
def init_db():
    """Creates the database tables."""
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit() #수행 결과가 데이터베이스에 반영 후 영속적으로 남아있게 한다.

#기능 구현을 위해 user테이블에서 사용자명 검색 기능
def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = g.db.execute('select user_id from user where username = ?',
                      [username]).fetchone()
    return  rv[0] if rv else None

#사용자 등록 기능(회원가입)
@app.route('/register',methods=['GET','POST'])
def register():
    """Register the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None

    if request.method == 'POST':
        if not request.form['username']:
            error = ' You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a vaild email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            g.db.execute('''insert into user (
                   username, email, pw_hash) values (?, ?, ?)''',
                    [request.form['username'],request.form['email'],
                    generate_password_hash(request.form['password'])])
            g.db.commit()
            flash('You were successfully regustered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html',error=error)

#로그인(등록한 사용자명과 비밀번호 사용)
@app.route('/login', methods=['GET','POST'])
def login():
    """login the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user =query_db('''select * from user where
           username = ?''',[request.form['username']],one=True)
        if user is None:
            error = 'Invaild username'
        elif not check_password_hash(user['pw_hash'],
                                        request.form['password']):
            error = 'Invaild password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html',error=error)

#로그아웃, HTTP는 기본적으로 GET방식이다.
@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id',None)
    return redirect(url_for('public_timeline')) #모든유저의 타임라인이 공통으로 뜨는 타임라인으로 이동

#로그인 후 트윗(message) 등록, user_id로 로그인이 되었는지 안되었는지 확인한다.
@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        g.db.execute('''insert into 
            message (author_id, text, pub_date)
            values (?, ?, ?)''', (session['user_id'],
                                 request.form['text'],
                                 int(time.time())))
        g.db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))

#트윗 등록 후 생성되는 이미지는 gravatar라는 제공 서비스를 이용한 것
def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(),
            size)

#시간 표시 형식 설정
def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

#필터 등록 소스코드
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

#팔로우
@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user: #로그인 상태 확인
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    g.db.execute('insert into follower (who_id, whom_id) values (?, ?)',
                 [session['user_id'],whom_id])
    g.db.commit()
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline',username=username)) #내가 팔로우 한 유저의 타임라인으로 이동

#언팔로우
@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    g.db.execute('delete from follower where who_id=? and whom_id=?',
                 [session['user_id'],whom_id])
    g.db.commit()
    flash('You are no longer following "%s"' %username)
    return redirect(url_for('user_timeline',username=username)) #내가 언팔로우한 유저의 타임라인으로 이동

#모든 트윗이 보이는 타임라인
@app.route('/public')
def public_timeline():
    """Display the latest messages of all users."""
    return render_template('timeline.html',messages=query_db('''
    select message.*,user.* from message, user
    where message.author_id = user.user_id
    order by message.pub_date desc limit ?''', [PER_PAGE]))

#나와 내가 팔로우한 유저의 트윗이 보이는 타임라인(로그인상태 전제)
@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline. This timeline shows the user's
    message as well as all the message of followed users."""

    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html',messages=query_db('''
    select message.*, user.* from message, user
    where message.author_id = user.user_id and (
        user.user_id = ? or
        user.user_id in (select whom_id from follower
                                where who_id = ?))
    order by message.pub_date desc limit ?''',
    [session['user_id'],session['user_id'], PER_PAGE]))

#특정유저의 타임라인만 보여줌, 로그인 된 사용자가 요청한 타임라인의 사용자 팔로우 유무 확인
#본인의 팔로워인지 메시지 출력
@app.route('/<username>')
def user_timeline(username):
    """Display's a user tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username],one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
        follower.who_id = ? and follower.whom_id = ?''',
        [session['user_id'], profile_user['user_id']],
        one=True) is not None
    return render_template('timeline.html', messages=query_db('''
    select message.*, user.* from message, user where
    user.user_id = message.author_id and user.user_id = ?
    order by message.pub_date desc limit ?''',
    [profile_user['user_id'], PER_PAGE]), followed=followed,
    profile_user=profile_user)

@app.route('/loginCheck')
def logincheck():
    if g.user:
        flash("+login check")
    else:
        flash("login please")
    return render_template('logincheck.html')

@app.route('/sessions')
def sessions(): #지정해준 변수(a,b,c,cal)에 담긴 값을 연산하는 함수
    """calculator"""
    global a
    global b
    global c
    global cal

    if a is not None and b is not None:
        if cal=='+':
            c = str(float(a) + float(b))
        elif cal == '-':
            c = str(float(a) - float(b))
        elif cal == '*':
            c = str(float(a) * float(b))
        elif cal == '/':
            c = str(float(a) / float(b))
        else:
            cal = None
    return render_template('sessions.html', num=a ,num2=b, num3=c, cal=cal)

@app.route('/calculate2',methods=['POST'])
def calculate2(): #우리가 입력한 값을 지정해 준 변수(a,b,c,cal)에 담는 함수
    global a
    global b
    global cal

    if 'plus' in request.form:
        cal = '+'
    elif 'minus' in request.form:
        cal = '-'
    elif 'mul' in request.form:
        cal = '*'
    elif 'div' in request.form:
        cal = '/'
    else:
        cal = None

    if request.method == 'POST':
        if request.form['num']!='' and request.form['num2']!='':
            a = request.form['num']
            b = request.form['num2']
            return redirect(url_for('sessions'))
        else:
            a = request.form['num']
            b = request.form['num2']
            if a =='':
                if b =='':
                    a = None
                    b = None
                else:
                    a = None
            else:
                b = None
            return redirect(url_for('sessions'))

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

#작성된 코드 실행
if __name__=='__main__':
    init_db()
    app.run(host='0.0.0.0',debug=True)


