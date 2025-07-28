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
    id = db.Column(db.String(36), primary_key=True)  # Use string UUID as in your insert
    name = db.Column(db.String(100))
    type = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    unit = db.Column(db.String(20))
    image = db.Column(db.String(200))
    seller_username = db.Column(db.String(80))  # <- Add this
    description = db.Column(db.Text)            # <- Add this
    sold = db.Column(db.Integer, default=0)     # <- Add this


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(80), db.ForeignKey('user.username'))  # ✅ Proper FK to User
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)  # ✅ Proper FK to Product
    quantity = db.Column(db.Integer, default=1)

    # Relationships
    product = db.relationship('Product', backref='cart_items', lazy=True)






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
# ------------------ Define insert_fake_data FIRST ------------------
def insert_fake_data():
    if not User.query.filter_by(role='seller').first():
        seller1 = User(username='seller1', password=generate_password_hash('1234'), role='seller')
        db.session.add(seller1)
        db.session.commit()

    if not Product.query.first():
        p1 = Product(
            id=str(uuid.uuid4()),
            name='Rose Itra',
            type='Rose',
            quantity=100,
            unit='ml',
            price=150.0,
            seller_username='seller1',
            image='rose_itra.jpg',
            description='Classic rose fragrance.'
        )
        p2 = Product(
            id=str(uuid.uuid4()),
            name='Musk Itra',
            type='Musk',
            quantity=80,
            unit='ml',
            price=180.0,
            seller_username='seller1',
            image='musk_itra.jpg',
            description='Bold musk fragrance.'
        )
        db.session.add_all([p1, p2])
        db.session.commit()

# ------------------ THEN call it inside app context ------------------
with app.app_context():
    db.create_all()
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
            if role == 'seller'or role=='buyer':
                
                    # No need to touch sellers/carts dict
                flash(f"{role.capitalize()} created!", 'success')
            
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
    product = Product.query.filter_by(id=id, seller_username=username).first()
    if not product:
        flash("Product not found or unauthorized", "danger")
        return redirect('/seller_dashboard')

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.quantity = int(request.form['quantity'])
        product.type = request.form['type']
        product.unit = request.form['unit']
        product.description = request.form.get('description', product.description)

        image = request.files.get('image')
        if image and allowed_file(image.filename):
            filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            product.image = f'/static/uploads/{filename}'

        db.session.commit()
        flash("Product updated!", "success")
        return redirect('/seller_dashboard')

    return render_template('edit_product.html', product=product)


    # No need to touch sellers/carts dict
    flash(f"{role.capitalize()} created!", 'success')


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
    product = Product.query.filter_by(id=id).first()

    if not product:
        flash("Product not found", "danger")
        return redirect('/buyer_dashboard')

    new_cart_item = CartItem(buyer_username=username, product_id=product.id)
    db.session.add(new_cart_item)
    db.session.commit()

    flash(f"{product.name} added to cart!", "success")
    return redirect('/cart')


@app.route('/cart')
def cart():
    if 'username' not in session:
        flash("Please log in to view your cart.", "warning")
        return redirect('/login')

    username = session['username']
    user_cart_items = CartItem.query.filter_by(buyer_username=username).all()

    items = []
    total_price = 0

    for item in user_cart_items:
        product = Product.query.get(item.product_id)
        if product:
            item_info = {
                'product': product,
                'quantity': item.quantity,
                'subtotal': float(product.price) * item.quantity
            }
            items.append(item_info)
            total_price += item_info['subtotal']

    return render_template("cart.html", cart_items=items, total_price=total_price)

@app.route('/view_cart')
@login_required
@role_required('buyer')
def view_cart():
    username = session['username']
    cart_items = CartItem.query.filter_by(buyer_username=username).all()
    products = [Product.query.get(item.product_id) for item in cart_items]
    return render_template('cart.html', cart_items=products)



@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    all_products = Product.query.all()
    all_sellers = User.query.filter_by(role='seller').all()

    total_qty = sum(p.quantity + p.sold for p in all_products)
    total_sold = sum(p.sold for p in all_products)
    total_remaining = sum(p.quantity for p in all_products)
    total_revenue = sum(p.sold * p.price for p in all_products)

    seller_data = [{
        'seller': seller.username,
        'product_count': Product.query.filter_by(seller_username=seller.username).count()
    } for seller in all_sellers]

    type_counts = {}
    for p in all_products:
        type_counts[p.type] = type_counts.get(p.type, 0) + 1

    return render_template('admin_dashboard.html',
                           total_revenue=total_revenue,
                           total_products=len(all_products),
                           total_sold=total_sold,
                           total_sellers=len(seller_data),
                           seller_data=seller_data,
                           chart_labels=list(type_counts.keys()),
                           chart_data=list(type_counts.values()))

@app.route('/product_charts')
@login_required
@role_required('admin')
def product_charts():
    all_products = Product.query.all()

    type_counts = {}
    for p in all_products:
        t = p.type
        type_counts[t] = type_counts.get(t, 0) + 1

    return render_template('product_charts.html',
                           chart_labels=list(type_counts.keys()),
                           chart_data=list(type_counts.values()))

@app.route('/product_type_overview')
@login_required
@role_required('admin')
def product_type_overview():
    all_products = Product.query.all()
    counts = {}
    for p in all_products:
        counts[p.type] = counts.get(p.type, 0) + 1
    return render_template('product_type_overview.html', counts=counts)

@app.route('/product_sales_summary')
@login_required
@role_required('admin')
def product_sales_summary():
    all_products = Product.query.all()
    summary = []
    for p in all_products:
        summary.append({
            'name': p.name,
            'sold': p.sold,
            'revenue': p.sold * p.price
        })
    return render_template('product_sales_summary.html', summary=summary)


def seller_product_counts():
    sellers = User.query.filter_by(role='seller').all()
    return [{
        'seller': seller.username,
        'product_count': Product.query.filter_by(seller_username=seller.username).count()
    } for seller in sellers]


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
    all_products = Product.query.all()
    return render_template('product_gallery.html', products=all_products)


# ----------------- 404 Error Handler -----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404





if __name__ == '__main__':
    app.run(debug=True)
