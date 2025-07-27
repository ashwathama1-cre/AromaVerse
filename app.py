from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
import uuid

# ------------------ Load Environment Variables ------------------
load_dotenv()

# ------------------ Flask App Configuration ------------------
app = Flask(__name__)

# Use secret key from environment variable
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# ------------------ Simulated Database ------------------
products = []
sellers = {}
users = {
    'admin': {'password': generate_password_hash('1234'), 'role': 'admin'}
}
carts = {}
# ------------------ Utility Functions ------------------

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

def filter_products_by_type(products, scent_type):
    if scent_type:
        return [p for p in products if p['type'].lower() == scent_type.lower()]
    return products

def send_email(to, message):
    print(f"[EMAIL TO: {to}] {message}")

# ------------------ Routes ------------------

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect('/admin_dashboard')
            elif user['role'] == 'seller':
                return redirect('/seller_dashboard')
            else:
                carts.setdefault(username, [])
                return redirect('/buyer_dashboard')
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

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
        if username in users:
            flash('User already exists!', 'danger')
        else:
            users[username] = {
                'password': generate_password_hash(password),
                'role': role
            }
            if role == 'seller':
                sellers[username] = []
            if role == 'buyer':
                carts[username] = []
            flash('User added successfully!', 'success')
    return render_template('add_user.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = success = None
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        confirm = request.form['confirm']
        username = session['username']
        if check_password_hash(users[username]['password'], current):
            if new == confirm:
                users[username]['password'] = generate_password_hash(new)
                success = 'Password changed successfully!'
                flash(success, 'success')
            else:
                error = 'New passwords do not match!'
                flash(error, 'danger')
        else:
            error = 'Current password is incorrect!'
            flash(error, 'danger')
    return render_template('change_password.html', error=error, success=success)

@app.route('/seller_dashboard')
@login_required
@role_required('seller')
def seller_dashboard():
    username = session['username']
    seller_products = sellers.get(username, [])
    scent_filter = request.args.get('filter')
    filtered = filter_products_by_type(seller_products, scent_filter)
    return render_template('seller_dashboard.html', products=filtered, scent_filter=scent_filter)

@app.route('/add_product', methods=['POST'])
@login_required
@role_required('seller')
def add_product():
    name = request.form['name']
    price = request.form['price']
    quantity = request.form['quantity']
    type_ = request.form['type']
    unit = request.form['unit']
    image = request.files['image']
    if image and allowed_file(image.filename):
        filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_path = UPLOAD_FOLDER + filename
    else:
        flash('Invalid image file!', 'danger')
        return redirect('/seller_dashboard')

    new_product = {
        'id': str(uuid.uuid4()),
        'name': name,
        'price': price,
        'quantity': quantity,
        'type': type_,
        'unit': unit,
        'image': image_path,
        'seller': session['username']
    }
    sellers[session['username']].append(new_product)
    flash('Product added successfully!', 'success')
    return redirect('/seller_dashboard')

@app.route('/delete_product/<id>')
@login_required
@role_required('seller')
def delete_product(id):
    username = session['username']
    seller_products = sellers.get(username, [])
    for p in seller_products:
        if p['id'] == id:
            seller_products.remove(p)
            flash('Product deleted!', 'warning')
            break
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

                image = request.files.get('image')
                if image and allowed_file(image.filename):
                    filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    product['image'] = UPLOAD_FOLDER + filename

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
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    scent_filter = request.args.get('filter')
    filtered = filter_products_by_type(all_products, scent_filter)
    return render_template('buyer_dashboard.html', products=filtered, scent_filter=scent_filter)

@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    return render_template('admin_dashboard.html', products=all_products)

@app.route('/add_to_cart/<id>', methods=['POST'])
@login_required
@role_required('buyer')
def add_to_cart(id):
    username = session['username']
    for product_list in sellers.values():
        for p in product_list:
            if p['id'] == id:
                carts[username].append(p.copy())
                flash('Product added to cart!', 'success')
                return redirect('/buyer_dashboard')
    flash('Product not found.', 'danger')
    return redirect('/buyer_dashboard')

@app.route('/cart')
@login_required
@role_required('buyer')
def view_cart():
    username = session['username']
    cart_items = carts.get(username, [])
    total_price = sum(int(item['price']) for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/remove_from_cart/<id>', methods=['POST'])
@login_required
@role_required('buyer')
def remove_from_cart(id):
    username = session['username']
    cart = carts.get(username, [])
    for item in cart:
        if item['id'] == id:
            cart.remove(item)
            flash('Item removed from cart.', 'info')
            break
    return redirect('/cart')

@app.route('/checkout')
@login_required
@role_required('buyer')
def checkout():
    username = session['username']
    cart_items = carts.get(username, [])
    if not cart_items:
        flash('Your cart is empty.', 'warning')
        return redirect('/cart')
    total = sum(int(item['price']) for item in cart_items)
    send_email(username, f"Thanks for purchasing! Total: ₹{total}")
    carts[username] = []  # Clear cart
    flash(f'Purchase successful! Total charged: ₹{total}', 'success')
    return redirect('/buyer_dashboard')

# ------------------ Main ------------------

if __name__ == '__main__':
    app.run(debug=True)

