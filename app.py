from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

from flask import jsonify

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
csrf = CSRFProtect(app) 
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
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # ✅ Use Integer auto ID
    name = db.Column(db.String(100))
    type = db.Column(db.String(50))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    sold = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(10))
    image = db.Column(db.String(100))
    description = db.Column(db.Text)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(80), db.ForeignKey('user.username'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)  # ✅ Make sure it's Integer
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product', backref='cart_items', lazy=True)


    # Relationship
    product = db.relationship('Product', backref='cart_items', lazy=True)


class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_username = db.Column(db.String(100), db.ForeignKey('user.username'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product_name = db.Column(db.String(200))
    price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    seller_id = db.Column(db.Integer)  # To identify seller
    address = db.Column(db.String(300))  # Optional, for shipping info


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
# ------------------ Routes ------------------

# (your route code goes here...)

@app.route('/reset_db')
def reset_db():
    db.drop_all()
    db.create_all()
    return "Database reset."



@app.route("/insert_attars")
@role_required("admin")
def trigger_insertion():
    insert_attar_products()
    return "✅ Sample attars inserted."



# insert 
import uuid

def insert_attar_products():
   

    # Ensure a default seller exists
    seller = User.query.filter_by(username="admin_seller").first()
    if not seller:
        seller = User(username="admin_seller", email="admin@attar.com", role="seller", password="1234")
        db.session.add(seller)
        db.session.commit()

    # Sample attars
    attars = [
        {
            "name": "Rose Attar",
            "type": "Rose",
            "price": 150,
            "quantity": 100,
            "image": "rose.jpg",
            "description": "Rich floral aroma with sweet, honey-like rose notes. Steam-distilled from rose petals into sandalwood oil."
        },
        {
            "name": "Mogra Attar",
            "type": "Jasmine",
            "price": 180,
            "quantity": 80,
            "image": "mogra.jpg",
            "description": "Intense creamy floral from jasmine blossoms. Known for uplifting romance and soothing nerves."
        },
        {
            "name": "Chandan Attar",
            "type": "Sandalwood",
            "price": 200,
            "quantity": 60,
            "image": "chandan.jpg",
            "description": "Creamy-woody aroma. Distilled from sandalwood heartwood. Ideal for meditation."
        },
        {
            "name": "Mitti Attar",
            "type": "Earth",
            "price": 130,
            "quantity": 100,
            "image": "mitti.jpg",
            "description": "Petrichor scent of first rain on earth. Made from baked soil and sandalwood."
        },
        {
            "name": "Khus Attar",
            "type": "Vetiver",
            "price": 160,
            "quantity": 90,
            "image": "khus.jpg",
            "description": "Earthy and cooling. Extracted from vetiver roots into sandalwood."
        },
        {
            "name": "Kesar Attar",
            "type": "Saffron",
            "price": 300,
            "quantity": 50,
            "image": "kesar.jpg",
            "description": "Luxurious blend of saffron and sandalwood. Exotic, spicy-sweet scent."
        },
        {
            "name": "Shamama Attar",
            "type": "Herbal Blend",
            "price": 350,
            "quantity": 40,
            "image": "shamama.jpg",
            "description": "Complex mix of vetiver, saffron, spices. Macerated and layered over weeks."
        },
        {
            "name": "Black Musk Attar",
            "type": "Musk",
            "price": 250,
            "quantity": 30,
            "image": "black_musk.jpg",
            "description": "Deep earthy musk using herbal musk bases like vetiver and patchouli."
        },
        {
            "name": "Oudh Attar",
            "type": "Oudh",
            "price": 400,
            "quantity": 25,
            "image": "oudh.jpg",
            "description": "Powerful resinous fragrance from agarwood. Used in royalty and rituals."
        },
        {
            "name": "Amber Attar",
            "type": "Amber",
            "price": 280,
            "quantity": 45,
            "image": "amber.jpg",
            "description": "Warm sweet-earthy amber scent. Blended with labdanum and benzoin resins."
        }
    ]

    for a in attars:
     
     if not Product.query.filter_by(name=a['name']).first():
      
      new_product = Product(
      name=a['name'],
      type=a['type'],
      price=a['price'],
      quantity=a['quantity'],
      unit='ml',
      image=a['image'],
      description=a['description'],
      seller_id=seller.id
                         )

    db.session.add(new_product)

    db.session.commit()
    print("✅ Sample attar products inserted.")


# ------------------ Insert Sample Products ------------------

with app.app_context():
    if os.environ.get("FLASK_ENV") == "development" and os.path.exists("users.db"):
        os.remove("users.db")

    db.create_all()

    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('1234')
        admin = User(username='admin', password=hashed_pw, role='admin', email='admin@example.com')
        db.session.add(admin)

    if not User.query.filter_by(username='shaurya').first():
        hashed_pw = generate_password_hash('12345678')
        shaurya = User(username='shaurya', password=hashed_pw, role='seller', email='shaurya@example.com')
        db.session.add(shaurya)

    db.session.commit()

    # ✅ Call after functions are defined
    insert_fake_data()
    insert_attar_products()


 


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

from random import randint
otp_storage = {}

# Dummy in-memory database (replace with SQLAlchemy for production)
users = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        session['email'] = email

        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['otp_time'] = datetime.now()

        flash(f"OTP sent to your email! (Simulated OTP: {otp})", "info")  # In production, send via email/SMS
        return redirect('/verify_otp')

    return render_template('register.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    otp_data = otp_storage.get(email)

    if not otp_data:
        flash("OTP session expired. Please request again.", "danger")
        return redirect('/')

    time_left = (otp_data['expires'] - datetime.now()).total_seconds()

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if datetime.now() > otp_data['expires']:
            flash("⏰ OTP expired! Please request again.", "danger")
            return redirect('/')
        if entered_otp == otp_data['otp']:
            flash("✅ OTP Verified!", "success")
            del otp_storage[email]
            return redirect('/dashboard')
        else:
            flash("❌ Incorrect OTP!", "danger")
            return redirect(url_for('verify_otp'))

    return render_template("verify_otp.html", time_left=int(time_left))
@app.route('/dashboard')
def dashboard():
    email = session.get('email')
    if not email or email not in users:
        flash("Please register first.", "warning")
        return redirect('/register')

    return render_template('dashboard.html', email=email)

#>>>>>>>>>>send otp 


def generate_otp():
    return str(random.randint(100000, 999999))

otp_storage = {}

@app.route('/send_otp/<email>')
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    expiry_time = datetime.now() + timedelta(minutes=2)

    # Store OTP and expiry in session or dict
    otp_storage[email] = {'otp': otp, 'expires': expiry_time}

    print(f"OTP for {email}: {otp} (valid until {expiry_time.strftime('%H:%M:%S')})")  # Replace with email sending logic

    session['otp_email'] = email
    return redirect(url_for('verify_otp'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        method = request.form['method']  # 'email' or 'phone'
        contact = request.form['contact']
        otp = request.form['otp']
        new_password = request.form['new_password']

        # Simulate checking OTP (in real case, use session + email gateway or SMS API)
        if otp != "123456":
            flash("Invalid OTP. Try again.", "danger")
            return redirect(url_for('forgot_password'))

        # TODO: Lookup user and update password in database
        flash(f"Password updated successfully for {method}: {contact}", "success")
        return redirect(url_for('login'))

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
                flash('Password changed successfully.', 'success')  # ✅ Flash success message
                return redirect('/change_password')
            else:
                flash('New passwords do not match.', 'danger')  # ✅ Flash error message
        else:
            flash('Current password is incorrect.', 'danger')  # ✅ Flash error message

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
#>>>>>>>>>>selller data 

@app.route("/admin/seller_detail/<seller_id>")
@login_required
@role_required('admin')
def seller_detail(seller_id):
    seller = User.query.get(seller_id)
    if not seller:
        return jsonify({"error": "Seller not found"}), 404

    total_products = Product.query.filter_by(seller_id=seller_id).count()
    total_sold = db.session.query(db.func.sum(Product.quantity_sold)).filter_by(seller_id=seller_id).scalar() or 0
    revenue = db.session.query(
        db.func.sum(Product.quantity_sold * Product.price)
    ).filter_by(seller_id=seller_id).scalar() or 0

    return jsonify({
        "name": seller.username,
        "email": seller.email,
        "total_products": total_products,
        "total_sold": total_sold,
        "revenue": float(revenue)
    })

    try:
     
     some_code_here()
    except Exception as e:
     
     print(e)




#####>>>>>>>>>>>>>>>>>>>manage seller
@app.route("/seller_overview")
@login_required
@role_required('admin')
def seller_overview():
    sellers = Seller.query.all()
    seller_counts = {}
    seller_ids = {}
    for s in sellers:
        count = Product.query.filter_by(seller_id=s.id).count()
        seller_counts[s.username] = count
        seller_ids[s.username] = s.id
    return render_template("manage_sellers.html", seller_counts=seller_counts, seller_ids=seller_ids)





#>>>>>>>>>>>>>>promote buyer 
@app.route('/promote_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def promote_user(user_id):
    user = User.query.get(user_id)
    if user and user.role == 'buyer':
        user.role = 'seller'
        db.session.commit()
        flash(f"✅ {user.username} is now a Seller!", "success")
    return redirect(url_for('manage_users'))


@app.route('/add_product', methods=['POST'])
@role_required('seller')
def add_product():
    name = request.form['name']
    type = request.form['type']
    price = float(request.form['price'])
    quantity = int(request.form['quantity'])
    unit = request.form['unit']
    image = request.files['image']
    filename = secure_filename(image.filename)
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    description = request.form.get('description')
    seller_id = get_current_user().id  # Assuming you're fetching logged-in seller

    # ✅ Automatically assign ID
    new_product = Product(
        name=name,
        type=type,
        price=price,
        quantity=quantity,
        unit=unit,
        image=filename,
        description=description,
        seller_id=seller_id
    )
    db.session.add(new_product)
    db.session.commit()

    flash("✅ Product added successfully", "success")
    return redirect('/seller_dashboard')


#---------------get selller detail----------------

@app.route('/admin/seller/<int:seller_id>')
@login_required
@role_required('admin')
def get_seller_detail(seller_id):
    seller = Seller.query.get_or_404(seller_id)
    product_count = Product.query.filter_by(seller_id=seller.id).count()
    revenue = db.session.query(db.func.sum(Product.price * Product.sold_qty)).filter_by(seller_id=seller.id).scalar() or 0

    return jsonify({
        "username": seller.username,
        "email": seller.email,
        "aadhar": seller.aadhar,
        "address": seller.address,
        "photo": seller.photo,
        "products": product_count,
        "revenue": revenue
    })


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
@app.route('/add_to_cart/<int:id>')
@login_required
@role_required('buyer')
def add_to_cart(id):
    username = session.get('username')

    try:
        product = Product.query.get_or_404(id)

        # Check if product has stock
        if product.quantity <= 0:
            flash("⚠️ This product is out of stock.", "warning")
            return redirect('/buyer_dashboard')

        # Add or update cart item
        existing_item = CartItem.query.filter_by(buyer_username=username, product_id=id).first()
        if existing_item:
            if product.quantity >= existing_item.quantity + 1:
                existing_item.quantity += 1
            else:
                flash("⚠️ Not enough stock available.", "warning")
                return redirect('/cart')
        else:
            new_item = CartItem(buyer_username=username, product_id=id, quantity=1)
            db.session.add(new_item)

        db.session.commit()
        flash(f"✅ {product.name} added to cart!", "success")
        return redirect('/cart')

    except Exception as e:
        print("Add to Cart Error:", e)
        flash("❌ Failed to add product to cart.", "danger")
        return redirect('/buyer_dashboard')


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

        # Chart Data: Count products by type
        type_counts = db.session.query(Product.type, func.count(Product.id)).group_by(Product.type).all()
        chart_labels = [t[0] for t in type_counts]
        chart_data = [t[1] for t in type_counts]

        # Seller Overview Table
        seller_data = db.session.query(
            User.id.label("id"),
            User.username.label("seller"),
            User.email.label("email"),
            func.count(Product.id).label("product_count")
        ).join(Product, Product.seller_id == User.id).filter(User.role == 'seller').group_by(User.id).all()

        # 🆕 Fetch all products with seller name for table display
        products = db.session.query(
           Product.id,
           Product.image,
           Product.name,
           Product.type,
           Product.description,
           Product.price,
           Product.quantity,
           Product.sold,
           Product.seller_id,
           User.username.label("seller_name")
                       ).outerjoin(User, Product.seller_id == User.id).all()
           

        # Commission Logic
        commission = 0
        purchases = Purchase.query.all()
        for p in purchases:
            if 'oud' in p.product_name.lower():
                commission += 10
            else:
                commission += 5

        total_unsold = db.session.query(func.sum(Product.quantity)).scalar() or 0

        return render_template("admin_dashboard.html",
                               total_revenue=total_revenue,
                               total_products=total_products,
                               total_sold=total_sold,
                               total_sellers=total_sellers,
                               chart_labels=chart_labels,
                               chart_data=chart_data,
                               seller_data=seller_data,
                               commission=commission,
                               total_unsold=total_unsold,
                               products=products)  # Pass products to template

    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<h2>Internal Error in /admin_dashboard:</h2><pre>{str(e)}</pre>", 500


#>>>>>>>>>>>>>>>>>>>>>> admin work 
# ✅ Product stats table by type
@app.route('/admin/product_stats')
@login_required
@role_required('admin')
def admin_product_stats():
    type_counts = db.session.query(
        Product.type,
        func.count(Product.id).label('count'),
        func.sum(Product.quantity).label('remaining')
    ).group_by(Product.type).all()

    return render_template('admin_product_stats.html', type_counts=type_counts)


# ✅ All products in tabular form
@app.route('/admin/products_table')
@login_required
@role_required('admin')
def admin_products_table():
    products = Product.query.all()
    return render_template('admin_products_table.html', products=products)
# admin change username


                           
@app.route('/change_name', methods=['GET', 'POST'])
@login_required
def change_name():
    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        new_name = request.form['new_name']

        # Check if new username is unique
        existing_user = User.query.filter_by(username=new_name).first()
        if existing_user:
            flash("Username already taken. Please choose another.", "warning")
        else:
            old_name = user.username
            user.username = new_name
            session['username'] = new_name  # Update session
            db.session.commit()
            flash("Username changed successfully!", "success")
            logging.info(f"{old_name} changed their username to {new_name}")
            return redirect(url_for('change_name'))

    return render_template('change_name.html', current_username=user.username)

#>>>>>>>>>>>>>>>>>>>>>>>>adminn product j
@app.route('/admin/products_json')
@login_required
@role_required('admin')
def admin_products_json():
    try:
        products = db.session.query(
            Product.id,
            Product.name,
            Product.type,
            Product.description,
            Product.image,
            Product.price,
            Product.quantity,
            Product.sold,
            User.username.label("seller_name")
        ).outerjoin(User, Product.seller_id == User.id).all()

        product_list = []

        for p in products:
            quantity_left = p.quantity
            revenue = p.price * p.sold
            commission = 10 * p.sold if 'oud' in (p.name or '').lower() else 5 * p.sold

            product_list.append({
                "id": p.id,
                "name": p.name,
                "type": p.type,
                "description": p.description or "No description provided",
                "image": url_for('static', filename='uploads/' + p.image) if p.image else "/static/default.png",
                "price": p.price,
                "left": quantity_left,
                "sold": p.sold,
                "revenue": revenue,
                "commission": commission,
                "seller": p.seller_name or "Unknown Seller"
            })

        return jsonify(product_list)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

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


#>>>>>>>>>Product sale historry 
@app.route('/sales_history')
@login_required
@role_required('admin')
def sales_history():
    sales = db.session.query(Purchase, Product).join(Product, Purchase.product_id == Product.id).all()
    return render_template('product_sales_summary.html', sales=sales)


#>>>>> manage seller 
@app.route('/manage_sellers', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_sellers():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form['username']
        
        if action == 'add':
            if not User.query.filter_by(username=username).first():
                new_user = User(username=username, role='seller', password=generate_password_hash('1234'))
                db.session.add(new_user)
                flash("✅ Seller added", "success")
        elif action == 'delete':
            user = User.query.filter_by(username=username, role='seller').first()
            if user:
                db.session.delete(user)
                flash("🗑️ Seller deleted", "warning")

        db.session.commit()
    sellers = User.query.filter_by(role='seller').all()
    return render_template("seller_manage.html", sellers=sellers)

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


#>>>>>>>>>>>>>product detail>>>>>>>>>>>>
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)




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


@app.route("/insert_attars")
def insert_attars_once():
    if 'role' in session and session['role'] == 'admin':
        insert_attar_products()
        return "✅ Attars inserted."
    else:
        return "Unauthorized", 403



# ----------------- 404 Error Handler -----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


# ----------------- Main App Entry -----------------
if __name__ == '__main__':
    app.run(debug=True)
