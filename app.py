from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from functools import wraps
from datetime import timedelta, datetime
from dotenv import load_dotenv
import os
import uuid
import logging
logging.basicConfig(level=logging.DEBUG)


# ------------------ Load Environment Variables ------------------
load_dotenv()

# ------------------ App Configuration ------------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'mydefaultsecret')

UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads/')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



 
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.permanent_session_lifetime = timedelta(minutes=30)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

csrf = CSRFProtect(app)

LOG_FILE = 'logs/error.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

# ------------------ MODELS ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True)  # ✅ Add this line


class Product(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(100))
    type = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    unit = db.Column(db.String(20))
    image = db.Column(db.String(200))
    description = db.Column(db.Text)
    sold = db.Column(db.Integer, default=0)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(80), db.ForeignKey('user.username'))
    product_id = db.Column(db.String(36), db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product', backref='cart_items', lazy=True)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(100), db.ForeignKey('user.username'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product_name = db.Column(db.String(200))
    price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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

def send_email(to, message):
    print(f"[EMAIL TO: {to}] {message}")

def insert_fake_data():
    try:
        if not User.query.filter_by(role='seller').first():
            seller = User(username='seller1', password=generate_password_hash('1234'), role='seller')
            db.session.add(seller)
            db.session.commit()

            if not Product.query.first():
                p1 = Product(
                    id=str(uuid.uuid4()),
                    name='Rose Itra',
                    type='Rose',
                    quantity=100,
                    unit='ml',
                    price=150.0,
                    seller_id=seller.id,
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
                    seller_id=seller.id,
                    image='musk_itra.jpg',
                    description='Bold musk fragrance.'
                )
                db.session.add_all([p1, p2])
                db.session.commit()
    except Exception as e:
        logging.error(f"Error inserting fake data: {str(e)}")

# ------------------ App Context Init ------------------

with app.app_context():
   if os.environ.get("FLASK_ENV") == "development" and os.path.exists("users.db"):

        os.remove("users.db")  # Only deletes DB in development mode

    db.create_all()

    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('1234')
        admin = User(username='admin', password=hashed_pw, role='admin', email='admin@example.com')
        db.session.add(admin)

    # ✅ Add shaurya seller user
    if not User.query.filter_by(username='shaurya').first():
        hashed_pw = generate_password_hash('12345678')
        shaurya = User(username='shaurya', password=hashed_pw, role='seller', email='shaurya@example.com')
        db.session.add(shaurya)

    db.session.commit()

    # Insert sample products
    insert_fake_data()


# ------------------ Routes ------------------


@app.before_request
def init_db_once():
    if not hasattr(app, 'db_initialized'):
        db.create_all()
        print("✅ Database initialized once.")
        app.db_initialized = True

def create_admin_if_not_exists():
    db.create_all()  # Ensure all tables are created
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        try:
            hashed_password = generate_password_hash('1234')
            new_admin = User(username='admin', password=hashed_password, role='admin')
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin user created with username='admin' and password='1234'")
        except Exception as e:
            logging.error(f"Failed to create admin user: {e}")
# route
@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['role'] = user.role
            session.permanent = True

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'seller':
                return redirect(url_for('seller_dashboard'))
            else:
                return redirect(url_for('buyer_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect('/login')

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


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash('❌ User already exists!', 'danger')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role=role
            )
            db.session.add(new_user)
            db.session.commit()

            flash(f"✅ {role.capitalize()} created successfully!", 'success')

    return render_template('add_user.html')


@app.route('/buy/<int:product_id>')
@login_required
@role_required('buyer')
def buy_product(product_id):
    product = Product.query.get_or_404(product_id)

    if product.quantity <= 0:
        flash("❌ Sorry, this product is out of stock.", "danger")
        return redirect('/buyer_dashboard')

    # Update product quantity and sold count
    product.quantity -= 1
    product.sold += 1

    # Update seller revenue
    seller = User.query.filter_by(username=product.seller).first()
    if seller:
        seller.revenue = (seller.revenue or 0) + product.price

    # Record purchase
    purchase = Purchase(
        buyer_username=session['username'],
        product_id=product.id,
        product_name=product.name,
        price=product.price,
        timestamp=datetime.utcnow()
    )
    db.session.add(purchase)
    db.session.commit()

    flash("✅ Product purchased successfully!", "success")
    return redirect('/buyer_dashboard')


@app.route('/update_quantity/<int:product_id>', methods=['POST'])
@login_required
@role_required('buyer')
def update_quantity(product_id):
    action = request.form.get('action')
    cart = session.get('cart', {})

    if str(product_id) in cart:
        if action == 'increase':
            cart[str(product_id)]['quantity'] += 1
        elif action == 'decrease' and cart[str(product_id)]['quantity'] > 1:
            cart[str(product_id)]['quantity'] -= 1

    session['cart'] = cart
    flash("🛒 Cart updated!", "success")
    return redirect('/cart')


@app.route('/checkout', methods=['POST'])
@login_required
@role_required('buyer')
def checkout():
    cart = session.get('cart', {})
    if not cart:
        flash("⚠️ Your cart is empty.", "warning")
        return redirect('/cart')

    buyer_username = session['username']

    for item in cart.values():
        product = Product.query.get(item['id'])
        if not product or product.quantity < item['quantity']:
            flash(f"❌ Not enough stock for {item['name']}.", "danger")
            return redirect('/cart')

        product.quantity -= item['quantity']
        product.sold += item['quantity']

        # Add to Purchase table
        for _ in range(item['quantity']):
            purchase = Purchase(
                buyer_username=buyer_username,
                product_id=product.id,
                product_name=product.name,
                price=product.price,
                timestamp=datetime.utcnow()
            )
            db.session.add(purchase)

        # Update seller revenue
        seller = User.query.filter_by(username=product.seller).first()
        if seller:
            seller.revenue = (seller.revenue or 0) + (product.price * item['quantity'])

    db.session.commit()
    session['cart'] = {}
    flash("✅ Purchase successful! Thank you.", "success")
    return redirect('/buyer_dashboard')


@app.route('/clear_cart')
@login_required
@role_required('buyer')
def clear_cart():
    session['cart'] = {}
    flash("🧹 Cart cleared successfully.", "info")
    return redirect('/cart')


@app.route('/buyer_profile')
@login_required
@role_required('buyer')
def buyer_profile():
    purchases = Purchase.query.filter_by(buyer_username=session['username']).order_by(Purchase.timestamp.desc()).all()
    return render_template("buyer_profile.html", purchases=purchases)


@app.route("/seller_dashboard")
@login_required
@role_required('seller')
def seller_dashboard():
    seller_id = session['user_id']
    products = Product.query.filter_by(seller_id=seller_id).all()

    notifications = []
    for p in products:
        if p.sold > 0:
            notifications.append(f'Your product "{p.name}" was sold ({p.sold} units).')

    return render_template("seller_dashboard.html", products=products, notifications=notifications)

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

    seller = User.query.filter_by(username=session['username']).first()
    if not seller:
        flash('❌ Seller not found.', 'danger')
        return redirect('/seller_dashboard')

    new_product = Product(
        id=str(uuid.uuid4()),
        name=name,
        price=price,
        quantity=quantity,
        sold=0,
        type=type_,
        unit=unit,
        image=image_path,
        seller_id=seller.id,
        description=description
    )

    db.session.add(new_product)
    db.session.commit()
    flash('✅ Product added successfully!', 'success')
    return redirect('/seller_dashboard')

# ------------------------- Delete Product -------------------------
@app.route('/delete_product/<id>')
@login_required
@role_required('seller')
def delete_product(id):
    seller = User.query.filter_by(username=session['username']).first()
    if not seller:
        flash("❌ Seller not found", "danger")
        return redirect('/seller_dashboard')

    product = Product.query.filter_by(id=id, seller_id=seller.id).first()
    if product:
        db.session.delete(product)
        db.session.commit()
        flash("✅ Product deleted successfully!", "success")
    else:
        flash("❌ Product not found or unauthorized access.", "danger")

    return redirect('/seller_dashboard')

# ------------------------- Edit Product -------------------------
@app.route('/edit_product/<id>', methods=['GET', 'POST'])
@login_required
@role_required('seller')
def edit_product(id):
    seller = User.query.filter_by(username=session['username']).first()
    if not seller:
        flash("❌ Seller not found", "danger")
        return redirect('/login')

    product = Product.query.filter_by(id=id, seller_id=seller.id).first()
    if not product:
        flash("❌ Product not found or unauthorized", "danger")
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
            filename = secure_filename(f"{uuid.uuid4().hex}_{image.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            product.image = f"/static/uploads/{filename}"

        db.session.commit()
        flash("✅ Product updated!", "success")
        return redirect('/seller_dashboard')

    return render_template('edit_product.html', product=product)



# filter product tpe
def filter_products_by_type(products, scent_type):
    if not scent_type:
        return products
    return [p for p in products if p.scent_type.lower() == scent_type.lower()]


# ------------------------- Buyer Dashboard -------------------------
@app.route('/buyer_dashboard')
@login_required
@role_required('buyer')
def buyer_dashboard():
    try:
        all_products = Product.query.all()
        scent_filter = request.args.get('filter')

        if scent_filter:
            filtered = [p for p in all_products if p.scent_type == scent_filter]
        else:
            filtered = all_products

        return render_template('buyer_dashboard.html', products=filtered, scent_filter=scent_filter)
    except Exception as e:
        print("Error in /buyer_dashboard:", e)
        return "Something went wrong in buyer dashboard", 500

# ------------------------- Add to Cart -------------------------
@app.route('/add_to_cart/<id>')
@login_required
@role_required('buyer')
def add_to_cart(id):
    username = session['username']
    product = Product.query.get(id)

    if not product:
        flash("❌ Product not found", "danger")
        return redirect('/buyer_dashboard')

    existing_item = CartItem.query.filter_by(buyer_username=username, product_id=id).first()
    if existing_item:
        existing_item.quantity += 1
    else:
        new_item = CartItem(buyer_username=username, product_id=id, quantity=1)
        db.session.add(new_item)

    db.session.commit()
    flash(f"✅ {product.name} added to cart!", "success")
    return redirect('/cart')

# ------------------------- View Cart -------------------------
@app.route('/cart')
@login_required
@role_required('buyer')
def cart():
    username = session.get('username')
    user_cart_items = CartItem.query.filter_by(buyer_username=username).all()

    items = []
    total_price = 0

    for item in user_cart_items:
        product = Product.query.get(item.product_id)
        if product:
            subtotal = float(product.price) * item.quantity
            items.append({'product': product, 'quantity': item.quantity, 'subtotal': subtotal})
            total_price += subtotal

    return render_template("cart.html", cart_items=items, total_price=total_price)

# ------------------------- Admin Dashboard -------------------------
@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    try:
        total_revenue = db.session.query(func.sum(Purchase.price)).scalar() or 0
        total_products = Product.query.count()
        total_sold = db.session.query(func.sum(Product.sold)).scalar() or 0
        total_sellers = User.query.filter_by(role='seller').count()

        type_counts = db.session.query(Product.type, func.count(Product.id)).group_by(Product.type).all()
        chart_labels = [t[0] for t in type_counts]
        chart_data = [t[1] for t in type_counts]

        seller_data = db.session.query(
         User.username.label("seller"),
           User.email.label("email"),
         func.count(Product.id).label("product_count")
            ).join(Product, Product.seller_id == User.id).filter(User.role == 'seller').group_by(User.id).all()


        return render_template("admin_dashboard.html",
                               total_revenue=total_revenue,
                               total_products=total_products,
                               total_sold=total_sold,
                               total_sellers=total_sellers,
                               chart_labels=chart_labels,
                               chart_data=chart_data,
                               seller_data=seller_data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<h2>Internal Error in /admin_dashboard:</h2><pre>{str(e)}</pre>", 500

# product chart 
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
        'product_count': Product.query.filter_by(seller_id=seller.id).count()
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
            return redirect('/reset_password')
    else:
        username = request.args.get('username', '')
        return render_template('reset_password.html', username=username)


@app.route('/remove_from_cart/<id>')
@login_required
@role_required('buyer')
def remove_from_cart(id):
    username = session['username']
    item = CartItem.query.filter_by(buyer_username=username, product_id=id).first()

    if not item:
        flash("Item not found in cart.", "warning")
        return redirect('/cart')

    if item.quantity > 1:
        item.quantity -= 1
    else:
        db.session.delete(item)

    db.session.commit()
    flash("Item removed from cart.", "success")
    return redirect('/cart')


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


# ----------------- Main App Entry -----------------
if __name__ == '__main__':
    app.run(debug=True)
