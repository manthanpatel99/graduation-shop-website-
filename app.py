from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database import connect_to_database, execute_query
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Set the login view

class User(UserMixin):
    def __init__(self, user_id, email, first_name, last_name, address):
        self.id = user_id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.address = address


@login_manager.user_loader
def load_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    user_id = int(user_id)                                  # make sure user id is being passed as int()
    print("Executing Query:", query % user_id)
    result = execute_query(query, params=(user_id,), fetchone=True)
    print("Result:", result)

    if result:
        print("User returned.")
        # Assuming the structure of the result matches the User class
        return User(
            user_id=result['id'],
            email=result['email'],
            first_name=result['first_name'],
            last_name=result['last_name'],
            address=result['address']
        )

    print("No user returned.")
    return None


@app.route('/')
def home():
    # Check if the user is logged in
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # Fetch carousel data from the database
    query = "SELECT * FROM carousel"
    carousel_data = execute_query(query, fetchall=True)

    # User is authenticated, get user details
    user_details = current_user
    print("User Details being passed to home:", user_details.__dict__)  # Added this line for debugging

    return render_template('home.html', carousel_data=carousel_data, user_details=user_details)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = authenticate_user(email, password)

        if user:
            login_user(user)
            flash('Logged in successfully.', 'success')

            # Print user details for debugging
            print("User Details:", user.__dict__)

            # Redirect to the home page after successful login
            return redirect(request.args.get('next') or url_for('home'))

        else:
            flash('Login failed. Please check your email and password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('You have been logged out successfully.', 'success')
    else:
        flash('You are not logged in.', 'warning')

    return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        query = "INSERT INTO users (email, password, first_name, last_name, address) VALUES (%s, %s, %s, %s, %s)"
        execute_query(query, params=(email, hashed_password, first_name, last_name, address))

        print("User inserted.")

        # Optionally, you can automatically log in the user after signing up
        user = authenticate_user(email, password)
        if user:
            login_user(user)
            return redirect(url_for('home'))

    return render_template('signup.html')


def authenticate_user(email, password):
    print("Email to Authenticate:", email)  # Add this line for debugging

    # Query the database to check if the email exists
    query = "SELECT * FROM users WHERE email = %s"
    result = execute_query(query, params=(email,), fetchone=True)

    print("Result:", result)  # Add this line for debugging

    if result and check_password_hash(result['password'], password):
        return User(
            user_id=result['id'],
            email=result['email'],
            first_name=result['first_name'],
            last_name=result['last_name'],
            address=result['address']
        )

    return None


@app.route('/products', methods=['GET', 'POST'])
def products():
    if request.method == 'POST':
        product_id = request.form['product_id']
        add_to_cart(product_id)

    # Fetch product data from the database
    query = "SELECT * FROM products"
    products = execute_query(query, fetchall=True)

    # Count the number of products
    query_count = "SELECT COUNT(*) FROM products"
    product_count = execute_query(query_count, fetchone=True)[0]

    return render_template('products.html', products=products, product_count=product_count)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        checkout_selected_products()

    selected_products = session.get('selected_products', [])
    product_info = get_product_info(selected_products)

    # If the "Go to Checkout" button is clicked, clear the selected products
    if request.form.get('checkout'):
        session.pop('selected_products', None)

    return render_template('checkout.html', product_info=product_info)


def add_to_cart(product_id):
    selected_products = session.get('selected_products', [])
    selected_products.append(product_id)
    session['selected_products'] = selected_products


def checkout_selected_products():
    selected_products = session.get('selected_products', [])

    if current_user.is_authenticated:
        user_id = current_user.id
        total_amount, product_quantities = calculate_total_amount(selected_products)

        # Insert an entry into the 'orders' table with the user's full name
        user_query = "SELECT first_name, last_name FROM users WHERE id = %s"
        user = execute_query(user_query, params=(user_id,), fetchone=True)

        if user:
            user_full_name = f"{user['first_name']} {user['last_name']}"

            # Insert an entry into the 'orders' table
            order_query = "INSERT INTO orders (user_id, user_full_name, total_amount, order_date) VALUES (%s, %s, %s, %s) RETURNING id"
            order_id = execute_query(order_query, params=(user_id, user_full_name, total_amount, datetime.now()), fetchone=True)['id']

            # Insert entries into the 'order_items' table for each selected product
            for product_id, quantity in product_quantities.items():
                add_product_to_order(order_id, product_id, quantity)

            # Clear the selected products after successful checkout
            session.pop('selected_products', None)

            flash('Checkout successful. Thank you for your purchase!', 'success')
        else:
            flash('User not found.', 'danger')
    else:
        flash('Please log in to complete the checkout.', 'warning')

    return redirect(url_for('home'))


def calculate_total_amount(selected_products):
    # Fetch prices from the database and calculate the total amount and product quantities
    total_amount = 0.0
    product_quantities = {}

    for product_id in selected_products:
        # Fetch the price of each product from the database
        product_query = "SELECT id, price FROM products WHERE id = %s"
        product = execute_query(product_query, params=(product_id,), fetchone=True)

        if product:
            total_amount += float(product['price'])

            # Increment the quantity for this product in the dictionary
            product_quantities[product_id] = product_quantities.get(product_id, 0) + 1

    return total_amount, product_quantities


def add_product_to_order(order_id, product_id, quantity):
    # Fetch the product details from the database, including the product name
    product_query = "SELECT name, price FROM products WHERE id = %s"
    product = execute_query(product_query, params=(product_id,), fetchone=True)

    if not product:
        # Handle the case where the product with the given ID is not found
        return

    # Fetch the user details from the database
    user_query = "SELECT first_name, last_name FROM users WHERE id = %s"
    user = execute_query(user_query, params=(current_user.id,), fetchone=True)

    if not user:
        # Handle the case where the user with the given ID is not found
        return

    # Concatenate the first_name and last_name to get the full name
    user_full_name = f"{user['first_name']} {user['last_name']}"

    # Insert an entry into the 'order_items' table with the correct quantity
    order_item_query = """
        INSERT INTO order_items (order_id, product_id, user_full_name, product_name, quantity, price)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    execute_query(
        order_item_query,
        params=(order_id, product_id, user_full_name, product['name'], quantity, product['price']),
    )


def get_product_info(product_ids):
    product_info = []
    for product_id in product_ids:
        query = "SELECT * FROM products WHERE id = %s"
        result = execute_query(query, params=(product_id,), fetchall=True)
        if result:
            product_info.append(result[0])
    return product_info


if __name__ == '__main__':
    app.run(debug=True)
