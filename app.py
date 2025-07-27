from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import os
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Upload folder
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.permanent_session_lifetime = timedelta(minutes=30)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# SQLAlchemy setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CSRF protection
csrf = CSRFProtect(app)

# ------------------- Models -------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    products = db.relationship('Product', backref='seller', lazy=True)
    cart_items = db.relationship('CartItem', backref='buyer', lazy=True)

class Product(db.Model):
    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    sold = db.Column(db.Integer, default=0)
    type = db.Column(db.String(50))
    unit = db.Column(db.String(20))
    image = db.Column(db.String(200))
    description = db.Column(db.Text)
    seller_username = db.Column(db.String(100), db.ForeignKey('user.username'))

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(100), db.ForeignKey('user.username'))
    product_id = db.Column(db.String(100), db.ForeignKey('product.id'))

with app.app_context():
    db.create_all()

# Now your models are correct and your app should save new users properly and resolve the foreign key error.
# Please ensure this code is merged at the top of your existing file before any logic that uses the models.




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash("Login required", "warning")
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') != role:
                flash("Access denied!", "danger")
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated
    return decorator
def filter_products_by_type(products_list, scent_type):
    if scent_type:
        return [p for p in products_list if p.type.lower() == scent_type.lower()]
    return products_list

def send_email(to, message):
    print(f"[EMAIL TO: {to}] {message}")

def calculate_stock_sold(products_list):
    total_qty = sum(int(p['quantity']) + int(p.get('sold', 0)) for p in products_list)
    total_sold = sum(int(p.get('sold', 0)) for p in products_list)
    total_remaining = sum(int(p['quantity']) for p in products_list)
    return total_qty, total_sold, total_remaining

def calculate_revenue(products_list):
    return sum(int(p.get('sold', 0)) * float(p['price']) for p in products_list)

def seller_product_counts():
    return [{
        'seller': name,
        'email': '',  # Removed in-memory users
        'product_count': len(prod_list)
    } for name, prod_list in sellers.items()]

def insert_fake_data():
    if not sellers:
        sellers['Shaurya'] = []
        sellers['Rehan'] = []
        sellers['Sara'] = []
    if not products:
        import random
        for seller in ['Shaurya', 'Rehan', 'Sara']:
            for i in range(3):
                p_id = str(uuid.uuid4())
                p_type = ['Rose', 'Musk', 'Oudh'][i % 3]
                prod = {
                    'id': p_id,
                    'name': f'{p_type} Perfume {i+1}',
                    'price': str(100 + i*50),
                    'quantity': '50',
                    'sold': str(random.randint(5, 30)),
                    'type': p_type,
                    'unit': 'ml',
                    'image': '/static/sample_perfume.jpg',
                    'seller': seller,
                    'description': f'A wonderful {p_type.lower()} scent with lasting aroma.'
                }
                sellers[seller].append(prod)
                products.append(prod)

insert_fake_data()

# ------------------- Routes -------------------

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            session.permanent = True
            if user.role == 'admin':
                return redirect('/admin_dashboard')
            elif user.role == 'seller':
                return redirect('/seller_dashboard')
            else:
                carts.setdefault(username, [])
                return redirect('/buyer_dashboard')
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
        elif password != confirm:
            flash('Passwords do not match!', 'warning')
        else:
            new_user = User(username=username, password=generate_password_hash(password), role='buyer')
            db.session.add(new_user)
            db.session.commit()
            carts[username] = []
            flash('Account created! Please login.', 'success')
            return redirect('/login')
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            send_email(user.username, f"Reset link: /reset_password?username={user.username}")
            flash('Password reset link sent.', 'info')
            return redirect('/login')
        flash('Username not found!', 'danger')
    return render_template('forgot_password.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        confirm = request.form['confirm']
        user = User.query.filter_by(username=session['username']).first()
        if user and check_password_hash(user.password, current):
            if new == confirm:
                user.password = generate_password_hash(new)
                db.session.commit()
                flash('Password changed!', 'success')
            else:
                flash('New passwords do not match!', 'danger')
        else:
            flash('Current password incorrect!', 'danger')
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect('/login')

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash('User already exists!', 'danger')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role=role
            )
            db.session.add(new_user)
            db.session.commit()

            # Add to sellers or carts dict (used for app logic)
            if role == 'seller':
                sellers[username] = []
            if role == 'buyer':
                carts[username] = []

            flash('User added successfully!', 'success')
    return render_template('add_user.html')



@app.route('/seller_dashboard')
@login_required
@role_required('seller')
def seller_dashboard():
    username = session['username']
    seller_products = Product.query.filter_by(seller_username=username).all()

    scent_filter = request.args.get('filter')
    filtered = filter_products_by_type(seller_products, scent_filter)
    return render_template('seller_dashboard.html', products=filtered, scent_filter=scent_filter)

@app.route('/add_product', methods=['POST'])
@login_required
@role_required('seller')
def add_product():
    name = request.form['name']
    price = float(request.form['price'])
    quantity = int(request.form['quantity'])
    type_ = request.form['type']
    unit = request.form['unit']
    description = request.form.get('description', '')
    image = request.files['image']

    if image and allowed_file(image.filename):
        filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)
        image_path = f"/static/uploads/{filename}"
    else:
        flash('❌ Invalid image file!', 'danger')
        return redirect('/seller_dashboard')

    # Save to database using SQLAlchemy
    new_product = Product(
        id=str(uuid.uuid4()),
        name=name,
        price=price,
        quantity=quantity,
        sold=0,
        type=type_,
        unit=unit,
        image=image_path,
        seller_username=session['username'],
        description=description
    )

    db.session.add(new_product)
    db.session.commit()

    flash('✅ Product added successfully!', 'success')
    return redirect('/seller_dashboard')

@app.route('/delete_product/<id>')
@login_required
@role_required('seller')
def delete_product(id):
    username = session['username']
    product = Product.query.filter_by(id=id, seller_username=username).first()
    if product:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'warning')
    else:
        flash('Product not found or unauthorized', 'danger')
    return redirect('/seller_dashboard')



@app.route('/edit_product/<id>', methods=['GET', 'POST'])
@login_required
@role_required('seller')
def edit_product(id):
    username = session['username']
    seller_products = sellers.get(username, [])
    for product in seller_products:
        if product['id'] == id:
            if request.method == 'POST':
                product['name'] = request.form['name']
                product['price'] = request.form['price']
                product['quantity'] = request.form['quantity']
                product['type'] = request.form['type']
                product['unit'] = request.form['unit']
                product['description'] = request.form.get('description', product.get('description',''))
                image = request.files.get('image')
                if image and allowed_file(image.filename):
                    filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(filepath)
                    product['image'] = f'/static/uploads/{filename}'
                flash('Product updated!', 'success')
                return redirect('/seller_dashboard')
            return render_template('edit_product.html', product=product)
    flash('Product not found', 'danger')
    return redirect('/seller_dashboard')

@app.route('/product/<id>')
@login_required
def product_detail(id):
    for product_list in sellers.values():
        for p in product_list:
            if p['id'] == id:
                return render_template('product_detail.html', product=p)
    flash('Product not found', 'danger')
    return redirect('/buyer_dashboard')

@app.route('/buyer_dashboard')
@login_required
@role_required('buyer')


def buyer_dashboard():
    all_products = Product.query.all()

    scent_filter = request.args.get('filter')
    filtered = filter_products_by_type(all_products, scent_filter)
    return render_template('buyer_dashboard.html', products=filtered, scent_filter=scent_filter)

@app.route('/add_to_cart/<id>')
@login_required
@role_required('buyer')
def add_to_cart(id):
    username = session['username']
    for product in products:
        if product['id'] == id:
            carts.setdefault(username, [])
            carts[username].append(product)
            flash(f"{product['name']} added to cart!", "success")
            break
    return redirect('/cart')


@app.route("/cart")
@login_required
@role_required('buyer')


def cart():
    username = session['username']
    cart_items = carts.get(username, [])
    total_price = sum(float(item['price']) for item in cart_items)
    return render_template("cart.html", cart_items=cart_items, total_price=total_price)


@login_required
@role_required('buyer')
def view_cart():
    username = session['username']
    user_cart = carts.get(username, [])
    return render_template('cart.html', products=user_cart)





@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)

    total_qty, total_sold, total_remaining = calculate_stock_sold(all_products)
    total_revenue = calculate_revenue(all_products)
    seller_counts = seller_product_counts()

    type_counts = {}
    for p in all_products:
        t = p['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    return render_template('admin_dashboard.html',
                           total_revenue=total_revenue,
                           total_products=len(all_products),
                           total_sold=total_sold,
                           total_sellers=len(seller_counts),
                           seller_data=seller_counts,
                           chart_labels=list(type_counts.keys()),
                           chart_data=list(type_counts.values()))
#new
@app.route('/product_charts')
@login_required
@role_required('admin')
def product_charts():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)

    type_counts = {}
    for p in all_products:
        t = p['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    return render_template('product_charts.html',
                           chart_labels=list(type_counts.keys()),
                           chart_data=list(type_counts.values()))


@app.route('/product_type_overview')
@login_required
@role_required('admin')
def product_type_overview():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    counts = {}
    for p in all_products:
        counts[p['type']] = counts.get(p['type'], 0) + 1
    return render_template('product_type_overview.html', counts=counts)

@app.route('/product_sales_summary')
@login_required
@role_required('admin')
def product_sales_summary():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    summary = []
    for p in all_products:
        summary.append({
            'name': p['name'],
            'sold': int(p.get('sold', 0)),
            'revenue': int(p.get('sold', 0)) * float(p['price'])
        })
    return render_template('product_sales_summary.html', summary=summary)

@app.route('/seller_overview')
@login_required
@role_required('admin')
def seller_overview():
    seller_counts = seller_product_counts()
    return render_template('seller_overview.html', seller_data=seller_counts)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password reset successfully! Please login.', 'success')
            return redirect('/login')
        else:
            flash('Invalid user.', 'danger')
            return redirect('/forgot_password')
    else:
        username = request.args.get('username', '')
        return render_template('reset_password.html', username=username)


@app.route('/product_gallery')
@login_required
@role_required('admin')
def product_gallery():
    # Gather all products for display
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)

    # Optionally add filtering/sorting here

    return render_template('product_gallery.html', products=all_products)

# ----------------- 404 Error Handler -----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404





if __name__ == '__main__':
    app.run(debug=True)
