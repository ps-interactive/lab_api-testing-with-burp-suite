#!/usr/bin/env python3
"""
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import jwt
import datetime
import json
import re

app = Flask(__name__)
app.secret_key = 'weak_secret_key_123'
CORS(app)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('vulnerable_graphql.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            api_key TEXT,
            secret_notes TEXT
        )
    ''')
    
    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT,
            category TEXT,
            internal_notes TEXT
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total_price REAL,
            status TEXT,
            admin_notes TEXT
        )
    ''')
    
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@company.com', 'admin', 'admin_key_12345', 'Admin has access to all systems')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password123', 'user1@company.com', 'user', 'user_key_67890', 'Regular user account')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'testuser', 'test123', 'test@company.com', 'user', 'test_key_54321', 'Test account for demos')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (4, 'alice', 'alice456', 'alice@company.com', 'manager', 'manager_key_99999', 'Manager level access')")
    
    cursor.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'High-performance laptop', 'Electronics', 'Cost: $500, Margin: 50%')")
    cursor.execute("INSERT OR IGNORE INTO products VALUES (2, 'Smartphone', 599.99, 'Latest smartphone model', 'Electronics', 'Cost: $300, Margin: 50%')")
    cursor.execute("INSERT OR IGNORE INTO products VALUES (3, 'Tablet', 399.99, 'Portable tablet device', 'Electronics', 'Cost: $200, Margin: 50%')")
    
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (1, 2, 1, 1, 999.99, 'completed', 'Expedited shipping approved')")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (2, 2, 2, 2, 1199.98, 'pending', 'Waiting for inventory')")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (3, 3, 3, 1, 399.99, 'shipped', 'VIP customer - priority handling')")
    
    conn.commit()
    conn.close()

def parse_graphql_query(query_string):
    """Simple GraphQL query parser - vulnerable to injection"""
    # Remove extra whitespace and newlines
    query = re.sub(r'\s+', ' ', query_string.strip())
    
    # Extract query type (query or mutation)
    if query.startswith('mutation'):
        query_type = 'mutation'
        query = query[8:].strip()
    else:
        query_type = 'query'
        if query.startswith('query'):
            query = query[5:].strip()
    
    return query_type, query

def execute_user_query(query, variables=None):
    """Execute user-related GraphQL queries - vulnerable to SQL injection"""
    conn = sqlite3.connect('vulnerable_graphql.db')
    cursor = conn.cursor()
    
    # Parse user ID from query (vulnerable parsing)
    if 'user(' in query:
        # Extract id parameter - vulnerable to injection
        id_match = re.search(r'id:\s*(\d+|[^,}]+)', query)
        if id_match:
            user_id = id_match.group(1)
            # Vulnerable SQL query
            sql_query = f"SELECT * FROM users WHERE id = {user_id}"
            try:
                cursor.execute(sql_query)
                user_data = cursor.fetchone()
                if user_data:
                    return {
                        "data": {
                            "user": {
                                "id": user_data[0],
                                "username": user_data[1],
                                "email": user_data[3],
                                "role": user_data[4],
                                "secretNotes": user_data[6]
                            }
                        }
                    }
            except Exception as e:
                return {"errors": [{"message": str(e)}]}
    
    # Parse username parameter - also vulnerable
    if 'username:' in query:
        username_match = re.search(r'username:\s*"([^"]*)"', query)
        if username_match:
            username = username_match.group(1)
            # Vulnerable SQL query
            sql_query = f"SELECT * FROM users WHERE username = '{username}'"
            try:
                cursor.execute(sql_query)
                user_data = cursor.fetchone()
                if user_data:
                    return {
                        "data": {
                            "user": {
                                "id": user_data[0],
                                "username": user_data[1],
                                "email": user_data[3],
                                "role": user_data[4],
                                "secretNotes": user_data[6]
                            }
                        }
                    }
            except Exception as e:
                return {"errors": [{"message": str(e)}]}
    
    # Handle users query (list all users)
    if 'users' in query and 'user(' not in query:
        # Extract limit if present
        limit = 10
        limit_match = re.search(r'limit:\s*(\d+)', query)
        if limit_match:
            limit = int(limit_match.group(1))
        
        # Vulnerable query with limit injection
        sql_query = f"SELECT * FROM users LIMIT {limit}"
        try:
            cursor.execute(sql_query)
            users_data = cursor.fetchall()
            users = []
            for user in users_data:
                users.append({
                    "id": user[0],
                    "username": user[1],
                    "email": user[3],
                    "role": user[4],
                    "secretNotes": user[6]
                })
            return {"data": {"users": users}}
        except Exception as e:
            return {"errors": [{"message": str(e)}]}
    
    conn.close()
    return {"data": None}

def execute_product_query(query):
    """Execute product-related GraphQL queries - vulnerable to injection"""
    conn = sqlite3.connect('vulnerable_graphql.db')
    cursor = conn.cursor()
    
    if 'products' in query:
        # Extract category parameter - vulnerable to injection
        category_match = re.search(r'category:\s*"([^"]*)"', query)
        search_match = re.search(r'search:\s*"([^"]*)"', query)
        
        if category_match and search_match:
            category = category_match.group(1)
            search = search_match.group(1)
            # Vulnerable union injection point
            sql_query = f"SELECT * FROM products WHERE category = '{category}' AND name LIKE '%{search}%'"
        elif category_match:
            category = category_match.group(1)
            sql_query = f"SELECT * FROM products WHERE category = '{category}'"
        elif search_match:
            search = search_match.group(1)
            sql_query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
        else:
            sql_query = "SELECT * FROM products"
        
        try:
            cursor.execute(sql_query)
            products_data = cursor.fetchall()
            products = []
            for product in products_data:
                products.append({
                    "id": product[0],
                    "name": product[1],
                    "price": product[2],
                    "description": product[3],
                    "category": product[4],
                    "internalNotes": product[5]
                })
            return {"data": {"products": products}}
        except Exception as e:
            return {"errors": [{"message": str(e)}]}
    
    conn.close()
    return {"data": None}

def execute_login_mutation(query):
    """Execute login mutation - vulnerable to SQL injection"""
    conn = sqlite3.connect('vulnerable_graphql.db')
    cursor = conn.cursor()
    
    # Extract username and password from mutation
    username_match = re.search(r'username:\s*"([^"]*)"', query)
    password_match = re.search(r'password:\s*"([^"]*)"', query)
    
    if username_match and password_match:
        username = username_match.group(1)
        password = password_match.group(1)
        
        # Vulnerable SQL injection in authentication
        sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(sql_query)
            user = cursor.fetchone()
            
            if user:
                token = jwt.encode({
                    'user_id': user[0],
                    'username': user[1],
                    'role': user[4],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }, app.secret_key, algorithm='HS256')
                
                return {
                    "data": {
                        "login": {
                            "success": "true",
                            "token": token,
                            "user": {
                                "id": user[0],
                                "username": user[1],
                                "role": user[4]
                            },
                            "message": "Authentication successful"
                        }
                    }
                }
            else:
                return {
                    "data": {
                        "login": {
                            "success": "false",
                            "message": "Invalid credentials",
                            "token": None,
                            "user": None
                        }
                    }
                }
        except Exception as e:
            return {"errors": [{"message": str(e)}]}
    
    conn.close()
    return {"errors": [{"message": "Invalid mutation format"}]}

# Simple GraphQL endpoint
@app.route('/graphql', methods=['GET', 'POST'])
def graphql():
    if request.method == 'GET':
        # Return GraphiQL interface
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>GraphiQL</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { display: flex; height: 80vh; }
                .query-section { flex: 1; margin-right: 10px; }
                .result-section { flex: 1; margin-left: 10px; }
                textarea { width: 100%; height: 300px; font-family: monospace; }
                button { padding: 10px 20px; background: #007cba; color: white; border: none; cursor: pointer; }
                .result { background: #f5f5f5; padding: 10px; height: 300px; overflow: auto; font-family: monospace; white-space: pre-wrap; }
                .example { background: #e8f4fd; padding: 10px; margin: 10px 0; border-left: 4px solid #007cba; }
            </style>
        </head>
        <body>
            <h1>GraphQL Testing Interface</h1>
            <div class="example">
                <strong>Example Queries:</strong><br>
                Query: { users { id username email role secretNotes } }<br>
                Mutation: mutation { login(username: "admin", password: "admin123") { success token user { username role } } }<br>
                Injection: { user(username: "admin' OR '1'='1'--") { id username role } }
            </div>
            <div class="container">
                <div class="query-section">
                    <h3>GraphQL Query</h3>
                    <textarea id="query" placeholder="Enter your GraphQL query here...">{ users { id username email role } }</textarea>
                    <br><br>
                    <button onclick="executeQuery()">Execute Query</button>
                </div>
                <div class="result-section">
                    <h3>Result</h3>
                    <div id="result" class="result">Results will appear here...</div>
                </div>
            </div>
            
            <script>
            function executeQuery() {
                const query = document.getElementById('query').value;
                
                fetch('/graphql', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ query: query })
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('result').textContent = JSON.stringify(data, null, 2);
                })
                .catch(error => {
                    document.getElementById('result').textContent = 'Error: ' + error;
                });
            }
            </script>
        </body>
        </html>
        '''
    
    elif request.method == 'POST':
        data = request.get_json()
        query = data.get('query', '')
        variables = data.get('variables', {})
        
        # Parse and execute GraphQL query
        query_type, parsed_query = parse_graphql_query(query)
        
        if query_type == 'mutation':
            if 'login' in parsed_query:
                return jsonify(execute_login_mutation(parsed_query))
        else:
            # Handle queries
            if 'user' in parsed_query:
                return jsonify(execute_user_query(parsed_query, variables))
            elif 'products' in parsed_query:
                return jsonify(execute_product_query(parsed_query))
            elif 'introspectionEnabled' in parsed_query:
                return jsonify({"data": {"introspectionEnabled": "GraphQL introspection is enabled - this should be disabled in production!"}})
        
        return jsonify({"data": None})

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({'status': 'GraphQL API is running', 'endpoint': '/graphql'})

# Rate limiting test endpoint (for Challenge 3)
@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    data = request.get_json()
    email = data.get('email', '')
    return jsonify({'message': f'Password reset link sent to {email}'}), 200

# API key test endpoint (for Challenge 3)
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    api_key = request.headers.get('X-API-Key')
    
    if not api_key or len(api_key) < 10:
        return jsonify({'error': 'Invalid API key'}), 401
    
    conn = sqlite3.connect('vulnerable_graphql.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    
    return jsonify([{
        'id': u[0],
        'username': u[1],
        'email': u[2],
        'role': u[3]
    } for u in users])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)
