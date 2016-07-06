import os
import re
import cgi
import string
import random
import hashlib
import hmac
import json
import time
from string import letters

import jinja2
import webapp2

from google.appengine.api import memcache
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

secret = 'somesecret'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]    
    if secure_val == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'        

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


def age_str(cache_time):
    age = int(time.time() - cache_time)
    return 'queried %s second%s ago' % (age, 's' if age != 1 else '')


def top_cache(update = False):    
    key = 'BLOGS'

    posts = memcache.get(key)

    if posts is None or update:
        q = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        posts = list(q)
        posts = (posts, time.time())
        memcache.set(key, posts)

    return posts

def single_cache(post_id):

    key = "post_" + post_id
    post = memcache.get(key)

    if not post:
        q = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(q)
        post = (post, time.time())
        memcache.set(key, post)
        top_cache(True)        

    return post

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class MainPage(Handler):
    def get(self):
        user = self.user
        if user:
            self.render('startpage.html', user = user.name)
        else:
            self.render('startpage.html')

class BlogFront(Handler):
    def get(self):
        user = self.user
        posts, age = top_cache()
        if self.format == 'html':
            if user:
                self.render('front.html', posts = posts, age = age_str(age), user = user.name)
            else:
                self.render('front.html', posts = posts, age = age_str(age))
        else:
            return self.render_json([p.as_dict() for p in posts])

class PostPage(Handler):
    def get(self, post_id):        
        user = self.user
        post, age = single_cache(post_id)        

        if self.format == 'html':
            self.render("permalink.html", post = post, age = age_str(age), user = user.name)
        else:
            self.render_json(post.as_dict())

class NewPost(Handler):
    def get(self):
        user = self.user
        if user:
            self.render("newpost.html", user = user.name)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            top_cache(True)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error, user = self.user)

class Flush(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


#
# Wiki stuff
#

class Page(db.Model):
    path = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    version = db.IntegerProperty(required = True)


class WikiMainPage(Handler):
    def get(self):
        wikis = db.GqlQuery("SELECT * FROM Page where version = 1 ORDER BY path DESC")
        wikis = list(wikis)

        user = self.user
        if user:
            self.render("main.html", wikis = wikis, user = user.name)
        else:
            self.render("main.html", wikis = wikis)


class WikiPost(Handler):
    def get(self, path):

        v = self.request.get("v")
        
        if v:
            v = int(v)
            q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 AND version = :2 ORDER BY created DESC", path, v).get()
            if not q:
                self.redirect(path)
        else:
            q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 ORDER BY created DESC", path).get()
            if not q:
                self.redirect("/wiki/_edit%s" % path)        
        
        if q:
            content = q.content
            if self.user:
                self.render("wikipage.html", path = path, user = self.user.name, content = content)
            else:
                self.render("wikipage.html", path = path, content = content)


class WikiEdit(Handler):
    def get(self, path):
        user = self.user        
        v = self.request.get("v")

        if user:
            if v:
                v = int(v)
                q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 AND version = :2 ORDER BY created DESC", path, v).get()
                if not q:
                    self.redirect("/wiki/_edit%s" % path)
            else:
                q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 ORDER BY created DESC", path).get()
                if not q:
                    self.render("editwiki.html", user = user.name, path = path)

            if q:                
                self.render("editwiki.html", user = user.name, path = q.path, content=q.content)
            
        else:
            self.redirect("/signup")

    def post(self, path):
        user = self.user
        content = self.request.get("content")

        if user:
            if content and path:
                q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 ORDER BY created DESC", path).get()
                if q:
                    cur_version = q.version + 1
                    page = Page(path = path, content = content, version = cur_version)
                    page.put()
                else:
                    page = Page(path = path, content = content, version = 1)
                    page.put()

                time.sleep(0.1)
                self.redirect("/wiki%s" % page.path)

            else:
                error = "content needed!"
                self.render("editwiki.html", user = user.name, error = error)
        else:
            self.redirect("/signup")


class WikiHistory(Handler):
    def get(self,path):        
        user = self.user
        if user:
            q = db.GqlQuery("SELECT * FROM Page WHERE path = :1 ORDER BY created DESC", path)
            if q :
                content = list(q)
                self.render("history.html", content = content, user = user.name)
            else:
                self.redirect("/wiki/_edit%s" % path)
        else:
            self.redirect("/signup")


class Signup(Handler):

    def get(self):
        next_url = self.request.headers.get('referer')
        self.render("signup-form.html", next_url = next_url)

    def post(self):
        next_url = str(self.request.get('next_url'))
        have_error = False        

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)

        else:
            
            u = User.by_name(self.username)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username = msg)
            else:

                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login(u)
                self.redirect(next_url)


class Login(Handler):
    def get(self):
        next_url = self.request.headers.get('referer')
        self.render('login-form.html', next_url = next_url)

    def post(self):
        next_url = str(self.request.get('next_url'))

        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(next_url)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(Handler):
    def get(self):
        next_url = self.request.headers.get('referer')
        self.logout()
        self.redirect(next_url)


class Cipher(Handler):
    def get(self):
        self.render('App.html')

    def post(self):        

        data2 = json.loads(self.request.body)        

        try:            
            data = data2["press"]
            text = data["text"]

            find_text = decryptText(text)
            output = {'text': find_text}
            output=json.dumps(output)
            self.response.out.headers = {'Content-Type': 'application/json; charset=utf-8'}
            self.response.out.write(output)

        except:            
            data = data2["click"] 

            text = data["text"]
            value = data["value"]
            shift = int(data["shift"])        

            if value == 'encrypt':
                new_text = encrypt(text, shift) 
            elif value == 'decrypt':
                new_text = decrypt(text, shift)
            
            message3 = numLetters(text)
            message2 = []
            for i in message3:
                message2.append({"breed":i, "number": message3[i]})

            output={'text': new_text, 'message2': message2}
            output=json.dumps(output)
            self.response.out.headers = {'Content-Type': 'application/json; charset=utf-8'}
            self.response.out.write(output)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)   


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app=webapp2.WSGIApplication([
            ('/', MainPage),
            ('/blog/?(?:.json)?', BlogFront),
            ('/blog/([0-9]+)(?:.json)?', PostPage),
            ('/blog/newpost', NewPost),
            ('/blog/flush', Flush),
            ('/wiki', WikiMainPage),
            ('/wiki/_edit' + PAGE_RE, WikiEdit),
            ('/wiki/_history' + PAGE_RE, WikiHistory),
            ('/signup', Signup),            
            ('/login', Login),
            ('/logout', Logout),
            ( '/wiki' + PAGE_RE , WikiPost),
            ( '/cipher' , Cipher),
            ], debug=True)




def escape_html(s):
    return cgi.escape(s, quote=True)



def wordsCoder(shift):
    """
    Returns a dict that can apply a Caesar cipher to a letter.
    The cipher is defined by the shift value. Ignores non-letter characters
    like punctuation, numbers and spaces.

    shift: 0 <= int < 26
    returns: dict
    """
    
    d = {}
    for i in range(len(string.ascii_lowercase)):
        s = (i + shift)  % 26
        c = string.ascii_lowercase[i]
        sc = string.ascii_lowercase[s]
        d[c] = sc
        d[c.upper()] = sc.upper()
    return d
    
def encrypt(text, shift):
    """
    Applies the wordsCoder to the text. Returns the encoded text.
    
    text: string
    shift: dict with mappings of characters to shifted characters    
    returns: text after wordsCoder to coded text
    """

    d = wordsCoder(shift)
    str = ''
    for i in text:
        if i in string.ascii_lowercase or i in string.ascii_uppercase:
            str+= d[i]
        else:
            str+=i
    return str

def decrypt(text, shift):
    """
    Applies the wordsCoder to the text. Returns the decoded text.

    text: string
    coder: dict with mappings of characters to shifted characters
    returns: text after wordsCoder to original text
    """
    shift = 26-shift
    d = wordsCoder(shift)
    str = ''
    for i in text:
        if i in string.ascii_lowercase or i in string.ascii_uppercase:
            str+= d[i]
        else:
            str+=i
    return str

def isWord(word):
    """
    Determines if english word is a valid word.

    Here is the list of all English words in the dictionary.
    word: a possible word.
    returns True if word is in wordList.

    Example:
    >>> isWord( 'bat') returns
    True
    >>> isWord('asdf') returns
    False
    """
    inFile = open('words.txt', 'r')
    wordList = inFile.read().split()
    
    word = word.lower()
    word = word.strip(" !@#$%^&*()-_+={}[]|\\:;'<>?,./\"")
    return word in wordList

def bestShift(text):
    """
    Finds a shift key that can decrypt the encoded text if.

    text: string
    returns: 0 <= int < 26
    """
    
    newText = text.split(' ')
    max_val = 0
    best_shift = 0
    best_text = ''
    for shft in range(26):
        num_valid = 0
        for word in newText:
            word = encrypt(word, shft)
            if isWord(word):
                num_valid+=1
                
        if num_valid > max_val:
            max_val = num_valid
            best_shift = shft
    
    return best_shift
    
def decryptText(text):
    """    
    Decrypts the text with bestShift function.
    
    text: string
    returns: string - story in plain text
    """
    
    return encrypt(text, bestShift(text))


def numLetters (text):
    """
    Finds how many times every letter appears in the text.
    Here we counting upper and lowercase characters together.

    text: string
    returns: dict
    """
    d = {}
    for letter in text.upper():
        if letter in string.ascii_uppercase:
            d[letter] = d.get(letter, 0) + 1 
    return d
