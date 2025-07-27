from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# In-memory data structures for demo
products = []
sellers = {}
users = {
    'admin': {'password': generate_password_hash('1234'), 'role': 'admin', 'email': 'admin@example.com'}
}
carts = {}

# -- Helper functions --

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
        return [p for p in products_list if p['type'].lower() == scent_type.lower()]
    return products_list

def send_email(to, message):
    print(f"[EMAIL TO: {to}] {message}")

def calculate_stock_sold(products_list):
    """Calculate total quantity, sold and remaining for all products combined"""
    total_qty = sum(int(p['quantity']) + int(p.get('sold', 0)) for p in products_list)
    total_sold = sum(int(p.get('sold', 0)) for p in products_list)
    total_remaining = sum(int(p['quantity']) for p in products_list)
    return total_qty, total_sold, total_remaining

def calculate_revenue(products_list):
    """Calculate total revenue from sold products"""
    total_revenue = 0
    for p in products_list:
        sold = int(p.get('sold', 0))
        price = float(p['price'])
        total_revenue += sold * price
    return total_revenue

def seller_product_counts():
    """Return a list of sellers with their product counts"""
    result = []
    for seller_name, prod_list in sellers.items():
        result.append({
            'seller': seller_name,
            'email': users.get(seller_name, {}).get('email', 'N/A'),
            'product_count': len(prod_list)
        })
    return result

# Insert some fake data for demonstration
def insert_fake_data():
    # Add sellers and products only if none exist
    if not sellers:
        sellers['Shaurya'] = []
        sellers['Rehan'] = []
        sellers['Sara'] = []
    if not products:
        # Add products for sellers
        import random
        for seller in ['Shaurya', 'Rehan', 'Sara']:
            for i in range(3):  # 3 products each
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
                    'image': '/static/sample_perfume.jpg',  # placeholder path
                    'seller': seller,
                    'description': f'A wonderful {p_type.lower()} scent with lasting aroma.'
                }
                sellers[seller].append(prod)
                products.append(prod)

insert_fake_data()

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if username in users:
            flash('Username already exists!', 'danger')
        elif any(email == user.get('email') for user in users.values()):
            flash('Email already registered!', 'danger')
        elif password != confirm:
            flash('Passwords do not match!', 'warning')
        else:
            users[username] = {
                'password': generate_password_hash(password),
                'email': email,
                'role': 'buyer'
            }
            carts[username] = []
            flash('Account created! Please login.', 'success')
            return redirect('/login')
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        for username, user in users.items():
            if user.get('email') == email:
                send_email(email, f"Hi {username}, your password reset link: example.com/reset/{username}")
                flash('Password reset instructions sent to your email.', 'info')
                return redirect('/login')
        flash('Email not found!', 'danger')
    return render_template('forgot_password.html')

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
                'role': role,
                'email': request.form.get('email', '')
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
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        confirm = request.form['confirm']
        username = session['username']
        if check_password_hash(users[username]['password'], current):
            if new == confirm:
                users[username]['password'] = generate_password_hash(new)
                flash('Password changed successfully!', 'success')
            else:
                flash('New passwords do not match!', 'danger')
        else:
            flash('Current password is incorrect!', 'danger')
    return render_template('change_password.html')

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
        'sold': '0',
        'type': type_,
        'unit': unit,
        'image': image_path,
        'seller': session['username'],
        'description': request.form.get('description', '')
    }
    sellers[session['username']].append(new_product)
    products.append(new_product)  # add to global products list
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
            # Also remove from global products list
            products[:] = [prod for prod in products if prod['id'] != id]
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
                product['description'] = request.form.get('description', product.get('description',''))
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
    # Aggregate all products for analytics
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    
    # Calculate stock & sales
    total_qty, total_sold, total_remaining = calculate_stock_sold(all_products)
    total_revenue = calculate_revenue(all_products)
    seller_counts = seller_product_counts()

    # Prepare product type counts
    type_counts = {}
    for p in all_products:
        t = p['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    return render_template('admin_dashboard.html',
                           products=all_products,
                           total_qty=total_qty,
                           total_sold=total_sold,
                           total_remaining=total_remaining,
                           total_revenue=total_revenue,
                           seller_counts=seller_counts,
                           type_counts=type_counts)

@app.route('/product_type_overview')
@login_required
@role_required('admin')
def product_type_overview():
    all_products = []
    for prod_list in sellers.values():
        all_products.extend(prod_list)
    # Count products by type
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
    # Calculate revenue & sold quantities per product
    summary = []
    for p in all_products:
        summary.append({
            'name': p['name'],
            'sold': int(p.get('sold', 0)),
            'revenue': int(p.get('sold', 0)) * float(p['price'])
        })
    return render_template('product_sales_summary.html', summary=summary)

@app.route('/add_to_cart/<id>', methods=['POST'])
@login_required
@role_required('buyer')
def add_to_cart(id):
    username = session['username']
    for product_list in sellers.values():
        for p in product_list:
            if p['id'] == id:
                carts[username].append(p.copy())
                # Increment sold count and reduce quantity
                if 'sold' not in p:
                    p['sold'] = '0'
                p['sold'] = str(int(p['sold']) + 1)
                p['quantity'] = str(max(0, int(p['quantity']) - 1))
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
    total_price = sum(float(item['price']) for item in cart_items)
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
    total = sum(float(item['price']) for item in cart_items)
    send_email(username, f"Thanks for purchasing! Total: ₹{total}")
    carts[username] = []
    flash(f'Purchase successful! Total charged: ₹{total}', 'success')
    return redirect('/buyer_dashboard')

# Run server
if __name__ == '__main__':
    app.run(debug=True)
