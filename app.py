import os
import json
import google.generativeai as genai
import mysql.connector
import jwt
import datetime
from functools import wraps # New import
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from flask_cors import CORS
from flask_bcrypt import Bcrypt

# --- Initialization & Configuration ---
load_dotenv()
app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '12345', # your database password
    'database': 'fin_advisor_db'
}

# --- NEW: Decorator for Token Authentication ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check if 'Authorization' header is present
        if 'Authorization' in request.headers:
            # The header should be in the format 'Bearer <token>'
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode the token using the secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # Find the user based on the ID from the token
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE id = %s", (data['user_id'],))
            current_user = cursor.fetchone()
            cursor.close()
            conn.close()
            if not current_user:
                 return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!'}), 401
        
        # Pass the user object to the decorated function
        return f(current_user, *args, **kwargs)
    return decorated


# --- User Authentication Endpoints (Unchanged) ---
@app.route('/signup', methods=['POST'])
def signup():
    # ... your existing signup code ...
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Username already exists"}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        return jsonify({"status": "success", "message": "User created successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    # ... your existing login code ...
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"status": "success", "token": token})
    except mysql.connector.Error as err:
        return jsonify({"status": "error", "message": "Database error"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()


# --- MODIFIED: Secured Expense Management Endpoint ---
@app.route('/add_expense', methods=['POST'])
@token_required # Apply the decorator
def add_expense_api(current_user): # The function now receives 'current_user'
    if not request.json or 'text' not in request.json:
        return jsonify({"status": "error", "message": "Missing 'text' in request body"}), 400
    
    expense_text = request.json['text']
    
    # Get the user ID from the token data passed by the decorator
    user_id = current_user['id']

    analyzed_data = analyze_expense(expense_text)
    if not analyzed_data:
        return jsonify({"status": "error", "message": "Failed to analyze expense text with AI"}), 500

    amount = analyzed_data.get('amount')
    category_name = analyzed_data.get('category')

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM categories WHERE name = %s", (category_name,))
        category_result = cursor.fetchone()
        
        if not category_result:
            return jsonify({"status": "error", "message": f"Category '{category_name}' not found"}), 400
        
        category_id = category_result[0]

        # Use the real user_id instead of the placeholder
        insert_query = "INSERT INTO expenses (amount, description, category_id, user_id) VALUES (%s, %s, %s, %s)"
        expense_data = (amount, expense_text, category_id, user_id)
        cursor.execute(insert_query, expense_data)
        
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

    return jsonify({
        "status": "success", 
        "message": "Expense added successfully",
        "data": {
            "amount": amount,
            "category": category_name
        }
    }), 201

# Add this new function inside your app.py

# Add this new function to your app.py

# Replace the existing get_dashboard_data function in app.py with this one

@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard_data(current_user):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT 
                c.id, c.name, b.amount AS budget,
                COALESCE(SUM(e.amount), 0) AS spent
            FROM categories c
            LEFT JOIN budgets b ON c.id = b.category_id AND b.user_id = %s
            LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = %s AND MONTH(e.expense_date) = MONTH(CURDATE()) AND YEAR(e.expense_date) = YEAR(CURDATE())
            GROUP BY c.id, c.name, b.amount
            ORDER BY c.id;
        """
        cursor.execute(query, (current_user['id'], current_user['id']))
        dashboard_data = cursor.fetchall()
        
        # --- MODIFICATION IS HERE ---
        # 1. Select the expense_date in the query
        cursor.execute("""
            SELECT e.description, e.amount, c.name as category, e.expense_date
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            WHERE e.user_id = %s 
            ORDER BY e.expense_date DESC 
            LIMIT 5
        """, (current_user['id'],))
        recent_expenses = cursor.fetchall()

        # 2. Format the datetime object into a string
        for expense in recent_expenses:
            expense['expense_date'] = expense['expense_date'].isoformat()
        # --- END OF MODIFICATION ---
        
        return jsonify({
            "status": "success", 
            "dashboard_data": dashboard_data,
            "recent_expenses": recent_expenses
        })

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/get_expenses', methods=['GET'])
@token_required
def get_expenses(current_user):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # SQL query to get expenses for the current user, joining with categories to get the category name
        query = """
            SELECT e.id, e.amount, e.description, e.expense_date, c.name as category
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            WHERE e.user_id = %s
            ORDER BY e.expense_date DESC
        """
        
        cursor.execute(query, (current_user['id'],))
        expenses = cursor.fetchall()

        # Convert datetime objects to string for JSON serialization
        for expense in expenses:
            expense['expense_date'] = expense['expense_date'].isoformat()

        return jsonify({"status": "success", "expenses": expenses})

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
# --- AI Core Function (Unchanged) ---
def analyze_expense(text):
    # ... your existing AI function code ...
    categories = ["Food", "Online Shopping", "Transport", "Entertainment", "Other"]
    prompt = f"""
    You are an intelligent expense categorizer. Analyze the following text and extract two pieces of information:
    1. The amount of money spent.
    2. The most likely category for the expense.
    The available categories are: {', '.join(categories)}.
    Analyze this text: "{text}"
    Your response MUST be a JSON object with two keys: "amount" (as a number) and "category" (as a string from the list).
    For example: {{"amount": 250, "category": "Food"}}
    """
    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        response_text = response.text.strip().replace('```json', '').replace('```', '').strip()
        result = json.loads(response_text)
        if "amount" in result and "category" in result:
            return result
        else:
            return None
    except Exception as e:
        print(f"Gemini analysis failed: {e}")
        return None
    
# Add these two new functions to your app.py

@app.route('/get_budgets', methods=['GET'])
@token_required
def get_budgets(current_user):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # This query gets all categories and joins any existing budget set by the user.
        query = """
            SELECT c.id, c.name, b.amount 
            FROM categories c 
            LEFT JOIN budgets b ON c.id = b.category_id AND b.user_id = %s
        """
        
        cursor.execute(query, (current_user['id'],))
        budgets = cursor.fetchall()

        return jsonify({"status": "success", "budgets": budgets})

    except mysql.connector.Error as err:
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/set_budget', methods=['POST'])
@token_required
def set_budget(current_user):
    data = request.get_json()
    category_id = data.get('category_id')
    amount = data.get('amount')

    if not category_id or amount is None:
        return jsonify({"status": "error", "message": "Category ID and amount are required"}), 400

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # This powerful SQL command inserts a new budget or updates it if one already exists for that user/category.
        query = """
            INSERT INTO budgets (user_id, category_id, amount) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE amount = VALUES(amount)
        """

        cursor.execute(query, (current_user['id'], category_id, amount))
        conn.commit()

        return jsonify({"status": "success", "message": "Budget saved successfully"})

    except mysql.connector.Error as err:
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# The /test route can be removed if you no longer need it.
@app.route('/test', methods=['GET'])
def test_route():
    return "Hello, the server is working!"