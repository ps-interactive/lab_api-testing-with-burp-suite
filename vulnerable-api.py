#!/usr/bin/env python3
"""
Vulnerable API for Burp Suite Testing Lab
Simulates common API vulnerabilities for educational purposes
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
import hashlib
import jwt
import datetime
import os
import json

app = Flask(__name__)
app.secret_key = 'weak_secret_key_123'
CORS(app)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('vulnerable_api.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            api_key TEXT
        )
    ''')
    
    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT,
            category TEXT
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
            status TEXT
        )
    ''')
    
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@company.com', 'admin', 'admin_key_12345')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password123', 'user1@company.com', 'user', 'user_key_67890')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'testuser', 'test123', 'test@company.com', 'user', 'test_key_54321')")
    
    cursor.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'High-performance laptop', 'Electronics')")
    cursor.execute("INSERT OR IGNORE INTO products VALUES (2, 'Smartphone', 599.99, 'Latest smartphone model', 'Electronics')")
    cursor.execute("INSERT OR IGNORE INTO products VALUES (3, 'Tablet', 399.99, 'Portable tablet device', 'Electronics')")
    
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (1, 2, 1, 1, 999.99, 'completed')")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (2, 2, 2, 2, 1199.98, 'pending')")
    
    conn.commit()
    conn.close()

# Vulnerable login endpoint (SQL Injection)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect('vulnerable_api.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query - susceptible to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'role': user[4],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.secret_key, algorithm='HS256')
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'role': user[4]
            }
        })
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

# Vulnerable user enumeration endpoint
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Missing authorization check - IDOR vulnerability
    conn = sqlite3.connect('vulnerable_api.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        })
    
    return jsonify({'error': 'User not found'}), 404

# Vulnerable products endpoint (NoSQL-style injection in filters)
@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category', '')
    price_filter = request.args.get('price_filter', '')
    
    conn = sqlite3.connect('vulnerable_api.db')
    cursor = conn.cursor()
    
    if category:
        # Vulnerable to injection
        query = f"SELECT * FROM products WHERE category = '{category}'"
        if price_filter:
            query += f" AND price {price_filter}"
        cursor.execute(query)
    else:
        cursor.execute("SELECT * FROM products")
    
    products = cursor.fetchall()
    
    return jsonify([{
        'id': p[0],
        'name': p[1],
        'price': p[2],
        'description': p[3],
        'category': p[4]
    } for p in products])

# Weak authentication endpoint
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    api_key = request.headers.get('X-API-Key')
    
    # Weak API key validation
    if not api_key or len(api_key) < 10:
        return jsonify({'error': 'Invalid API key'}), 401
    
    conn = sqlite3.connect('vulnerable_api.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    
    return jsonify([{
        'id': u[0],
        'username': u[1],
        'email': u[2],
        'role': u[3]
    } for u in users])

# Rate limiting bypass vulnerability
@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    data = request.get_json()
    email = data.get('email', '')
    
    # No rate limiting implemented
    return jsonify({'message': f'Password reset link sent to {email}'}), 200

# File upload vulnerability
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    # No file type validation
    filename = file.filename
    file.save(f'/tmp/{filename}')
    
    return jsonify({'message': f'File {filename} uploaded successfully'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)
