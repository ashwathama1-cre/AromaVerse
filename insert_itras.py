# insert_itras.py

from app import app, db, Product, User
import uuid

# Sample 10 Itra Data
itras = [
    {
        "name": "Rose Attar",
        "type": "Floral",
        "price": 150,
        "quantity": 100,
        "unit": "ml",
        "image": "rose.jpg",
        "description": "Rich floral aroma with sweet, honey‑like rose notes. Symbolic of love and spirituality."
    },
    {
        "name": "Mogra Attar",
        "type": "Floral",
        "price": 160,
        "quantity": 80,
        "unit": "ml",
        "image": "mogra.jpg",
        "description": "Sweet jasmine aroma. Intoxicating and romantic. Distilled in sandalwood oil."
    },
    {
        "name": "Chandan Attar",
        "type": "Woody",
        "price": 200,
        "quantity": 90,
        "unit": "ml",
        "image": "chandan.jpg",
        "description": "Creamy, woody scent. Calming and perfect for meditation. Made from pure sandalwood."
    },
    {
        "name": "Mitti Attar",
        "type": "Earthy",
        "price": 120,
        "quantity": 70,
        "unit": "ml",
        "image": "mitti.jpg",
        "description": "Smells like first rain on soil. Made from baked earth and sandalwood."
    },
    {
        "name": "Khus Attar",
        "type": "Earthy",
        "price": 140,
        "quantity": 85,
        "unit": "ml",
        "image": "khus.jpg",
        "description": "Vetiver-based attar. Rooty, cooling, and relaxing. Used in summer and calming routines."
    },
    {
        "name": "Kesar Attar",
        "type": "Spicy",
        "price": 250,
        "quantity": 50,
        "unit": "ml",
        "image": "kesar.jpg",
        "description": "Saffron-based. Warm, exotic, and luxurious scent. Rare and bold."
    },
    {
        "name": "Shamama Attar",
        "type": "Blend",
        "price": 300,
        "quantity": 60,
        "unit": "ml",
        "image": "shamama.jpg",
        "description": "Aged blend of herbs, spices, saffron, and wood oils. Strong, layered scent."
    },
    {
        "name": "Black Musk Attar",
        "type": "Musk",
        "price": 180,
        "quantity": 75,
        "unit": "ml",
        "image": "black_musk.jpg",
        "description": "Dark, mysterious musk scent with herbal depth. Inspired by Kasturi (non-animal)."
    },
    {
        "name": "Oudh Attar",
        "type": "Woody",
        "price": 400,
        "quantity": 40,
        "unit": "ml",
        "image": "oudh.jpg",
        "description": "Deep agarwood aroma. Resinous, luxurious and rich. Traditional and expensive."
    },
    {
        "name": "Amber Attar",
        "type": "Amber",
        "price": 220,
        "quantity": 65,
        "unit": "ml",
        "image": "amber.jpg",
        "description": "Sweet, warm, powdery scent. Blended from resins and vanilla notes. Long lasting."
    }
]

# Auto-generate 40 extra variants
extra_types = ["Floral", "Woody", "Spicy", "Musk", "Citrus"]
for i in range(40):
    base = itras[i % len(itras)].copy()
    base["name"] = f"{base['name'].split()[0]} Variant {i+1}"
    base["type"] = extra_types[i % len(extra_types)]
    base["price"] += (i % 5) * 10
    base["quantity"] = 50 + (i % 20) * 2
    base["image"] = f"{base['name'].lower().replace(' ', '_')}.jpg"
    itras.append(base)

# Insert into DB
with app.app_context():
    seller = User.query.filter_by(username='shaurya').first()
    if not seller:
        print("❌ Seller 'shaurya' not found. Please create it first in your DB.")
    else:
        added = 0
        for itra in itras:
            exists = Product.query.filter_by(name=itra['name'], seller_id=seller.id).first()
            if not exists:
                new_product = Product(
                    id=str(uuid.uuid4()),
                    name=itra['name'],
                    type=itra['type'],
                    price=itra['price'],
                    quantity=itra['quantity'],
                    unit=itra['unit'],
                    image=itra['image'],
                    description=itra['description'],
                    seller_id=seller.id
                )
                db.session.add(new_product)
                added += 1
        db.session.commit()
        print(f"✅ {added} Itra products added to database for seller '{seller.username}'.")
