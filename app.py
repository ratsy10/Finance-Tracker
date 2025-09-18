import os
import json
import jwt
import datetime
from functools import wraps
import google.generativeai as genai

# Import database libraries
import mysql.connector
import psycopg2
import dj_database_url

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

# --- MODIFIED: DYNAMIC DATABASE CONFIGURATION ---
IS_POSTGRES = False
if 'DATABASE_URL' in os.environ:
    # Production database configuration (PostgreSQL on Render)
    DB_CONFIG = dj_database_url.config(conn_max_age=600, ssl_require=False) # ssl_require might be needed depending on Render settings
    IS_POSTGRES = True
else:
    # Local development database configuration (MariaDB)
    DB_CONFIG = {
        'host': 'localhost',
        'user': 'root',
        'password': '12345', # your database password
        'database': 'fin_advisor_db'
    }

# Helper function to get a database connection
def get_db_connection():
    if IS_POSTGRES:
        return psycopg2.connect(
            dbname=DB_CONFIG['NAME'],
            user=DB_CONFIG['USER'],
            password=DB_CONFIG['PASSWORD'],
            host=DB_CONFIG['HOST'],
            port=DB_CONFIG['PORT']
        )
    else:
        return mysql.connector.connect(**DB_CONFIG)

# --- Decorator for Token Authentication (Updated to use get_db_connection) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True if not IS_POSTGRES else None) # psycopg2 doesn't have a built-in dict cursor this way
            
            cursor.execute("SELECT * FROM users WHERE id = %s", (data['user_id'],))
            current_user_tuple = cursor.fetchone()
            
            if not current_user_tuple:
                 return jsonify({'message': 'User not found!'}), 401
            
            # Convert tuple to dictionary if using psycopg2
            if IS_POSTGRES:
                current_user = {desc[0]: value for desc, value in zip(cursor.description, current_user_tuple)}
            else:
                current_user = current_user_tuple

        except Exception as e:
            print(f"Token error: {e}")
            return jsonify({'message': 'Token is invalid or expired!'}), 401
        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn' in locals(): conn.close()
            
        return f(current_user, *args, **kwargs)
    return decorated


# --- User Authentication Endpoints ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"status": "error", "message": "Username already exists"}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        return jsonify({"status": "success", "message": "User created successfully"}), 201
    except Exception as err:
        return jsonify({"status": "error", "message": f"Database error: {err}"}), 500
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True if not IS_POSTGRES else None)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_tuple = cursor.fetchone()

        if IS_POSTGRES and user_tuple:
            user = {desc[0]: value for desc, value in zip(cursor.description, user_tuple)}
        else:
            user = user_tuple

        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"status": "success", "token": token})
    except Exception as err:
        return jsonify({"status": "error", "message": f"Database error: {err}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn and conn.is_connected():
            conn.close()

# --- Expense & Budget Endpoints ---
@app.route('/add_expense', methods=['POST'])
@token_required
def add_expense_api(current_user):
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"status": "error", "message": "Missing 'text' in request body"}), 400
    
    expense_text = data['text']
    user_id = current_user['id']
    analyzed_data = analyze_expense(expense_text)

    if not analyzed_data:
        return jsonify({"status": "error", "message": "Failed to analyze expense text with AI"}), 500

    amount = analyzed_data.get('amount')
    category_name = analyzed_data.get('category')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM categories WHERE name = %s", (category_name,))
        category_result = cursor.fetchone()
        
        if not category_result:
            return jsonify({"status": "error", "message": f"Category '{category_name}' not found"}), 400
        
        category_id = category_result[0]
        insert_query = "INSERT INTO expenses (amount, description, category_id, user_id) VALUES (%s, %s, %s, %s)"
        cursor.execute(insert_query, (amount, expense_text, category_id, user_id))
        conn.commit()
    except Exception as err:
        print(f"Database Error: {err}")
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

    return jsonify({"status": "success", "message": "Expense added successfully", "data": analyzed_data}), 201

@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard_data(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True if not IS_POSTGRES else None)

        # SQL for MariaDB and PostgreSQL is slightly different for date functions
        date_filter_sql = "MONTH(e.expense_date) = MONTH(CURDATE()) AND YEAR(e.expense_date) = YEAR(CURDATE())"
        if IS_POSTGRES:
            date_filter_sql = "EXTRACT(MONTH FROM e.expense_date) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM e.expense_date) = EXTRACT(YEAR FROM CURRENT_DATE)"
            
        query = f"""
            SELECT c.id, c.name, b.amount AS budget, COALESCE(SUM(e.amount), 0) AS spent
            FROM categories c
            LEFT JOIN budgets b ON c.id = b.category_id AND b.user_id = %s
            LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = %s AND {date_filter_sql}
            GROUP BY c.id, c.name, b.amount
            ORDER BY c.id;
        """
        cursor.execute(query, (current_user['id'], current_user['id']))
        dashboard_tuples = cursor.fetchall()
        
        cursor.execute("""
            SELECT e.description, e.amount, c.name as category, e.expense_date
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            WHERE e.user_id = %s ORDER BY e.expense_date DESC LIMIT 5
        """, (current_user['id'],))
        recent_tuples = cursor.fetchall()

        if IS_POSTGRES:
            desc_dashboard = cursor.description
            dashboard_data = [{desc[0]: value for desc, value in zip(desc_dashboard, row)} for row in dashboard_tuples]
            desc_recent = cursor.description
            recent_expenses = [{desc[0]: value for desc, value in zip(desc_recent, row)} for row in recent_tuples]
        else:
            dashboard_data = dashboard_tuples
            recent_expenses = recent_tuples
        
        for expense in recent_expenses:
            if isinstance(expense['expense_date'], datetime.datetime):
                expense['expense_date'] = expense['expense_date'].isoformat()
        
        return jsonify({
            "status": "success", 
            "dashboard_data": dashboard_data,
            "recent_expenses": recent_expenses
        })
    except Exception as err:
        print(f"Database Error: {err}")
        return jsonify({"status": "error", "message": "Database operation failed"}), 500
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

@app.route('/get_budgets', methods=['GET'])
@token_required
def get_budgets(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True if not IS_POSTGRES else None)
        query = "SELECT c.id, c.name, b.amount FROM categories c LEFT JOIN budgets b ON c.id = b.category_id AND b.user_id = %s"
        cursor.execute(query, (current_user['id'],))
        budget_tuples = cursor.fetchall()
        
        if IS_POSTGRES:
            description = cursor.description
            budgets = [{desc[0]: value for desc, value in zip(description, row)} for row in budget_tuples]
        else:
            budgets = budget_tuples

        return jsonify({"status": "success", "budgets": budgets})
    except Exception as err:
        return jsonify({"status": "error", "message": f"Database error: {err}"}), 500
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

@app.route('/set_budget', methods=['POST'])
@token_required
def set_budget(current_user):
    data = request.get_json()
    category_id = data.get('category_id')
    amount = data.get('amount')

    if category_id is None or amount is None:
        return jsonify({"status": "error", "message": "Category ID and amount are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if IS_POSTGRES:
            # PostgreSQL uses ON CONFLICT
            query = """
                INSERT INTO budgets (user_id, category_id, amount) 
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id, category_id) 
                DO UPDATE SET amount = EXCLUDED.amount;
            """
        else:
            # MariaDB uses ON DUPLICATE KEY UPDATE
            query = """
                INSERT INTO budgets (user_id, category_id, amount) 
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE amount = VALUES(amount);
            """

        cursor.execute(query, (current_user['id'], category_id, amount))
        conn.commit()
        return jsonify({"status": "success", "message": "Budget saved successfully"})
    except Exception as err:
        return jsonify({"status": "error", "message": f"Database error: {err}"}), 500
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

# --- AI Core Function (Unchanged) ---
def analyze_expense(text):
    categories = ["Food", "Online Shopping", "Transport", "Entertainment", "Other"]
    prompt = f"""
    Analyze the following text and extract the amount of money spent and the most likely category.
    The available categories are: {', '.join(categories)}.
    Analyze this text: "{text}"
    Your response MUST be a JSON object with two keys: "amount" (as a number) and "category" (as a string from the list).
    """
    try:
        model = genai.GenerativeModel('gemini-pro')
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