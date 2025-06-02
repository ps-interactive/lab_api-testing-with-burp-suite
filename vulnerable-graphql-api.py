#!/usr/bin/env python3
"""
Vulnerable GraphQL API for Burp Suite Testing Lab
Simulates common GraphQL vulnerabilities for educational purposes
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import jwt
import datetime
import json
import graphene
from graphene import ObjectType, String, Int, Float, List, Field, Mutation, Schema, Argument
from flask_graphql import GraphQLView

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
    
    # Insert sample data with sensitive information
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

# GraphQL Type Definitions
class UserType(ObjectType):
    id = Int()
    username = String()
    email = String()
    role = String()
    secret_notes = String()  # Sensitive field that should be restricted

class ProductType(ObjectType):
    id = Int()
    name = String()
    price = Float()
    description = String()
    category = String()
    internal_notes = String()  # Sensitive field that should be restricted

class OrderType(ObjectType):
    id = Int()
    user_id = Int()
    product_id = Int()
    quantity = Int()
    total_price = Float()
    status = String()
    admin_notes = String()  # Sensitive field that should be restricted

class AuthPayload(ObjectType):
    success = String()
    token = String()
    user = Field(UserType)
    message = String()

# GraphQL Queries
class Query(ObjectType):
    # Vulnerable user query - susceptible to SQL injection and IDOR
    user = Field(UserType, id=Argument(Int), username=Argument(String))
    
    # Vulnerable users query - should require admin auth but doesn't
    users = List(UserType, limit=Argument(Int, default_value=10))
    
    # Vulnerable product search - susceptible to injection
    products = List(ProductType, category=Argument(String), search=Argument(String))
    
    # Product by ID - basic IDOR vulnerability
    product = Field(ProductType, id=Argument(Int, required=True))
    
    # Orders query - should check authorization but doesn't
    orders = List(OrderType, user_id=Argument(Int))
    
    # Schema introspection - should be disabled in production
    introspection_enabled = String()

    def resolve_user(self, info, id=None, username=None):
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        if id:
            # Vulnerable to SQL injection
            query = f"SELECT * FROM users WHERE id = {id}"
            cursor.execute(query)
        elif username:
            # Also vulnerable to SQL injection
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cursor.execute(query)
        else:
            return None
            
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return UserType(
                id=user_data[0],
                username=user_data[1],
                email=user_data[3],
                role=user_data[4],
                secret_notes=user_data[6]  # Leaking sensitive data
            )
        return None

    def resolve_users(self, info, limit):
        # No authentication check - IDOR vulnerability
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        # Vulnerable to injection through limit parameter
        query = f"SELECT * FROM users LIMIT {limit}"
        cursor.execute(query)
        users_data = cursor.fetchall()
        conn.close()
        
        return [
            UserType(
                id=user[0],
                username=user[1],
                email=user[3],
                role=user[4],
                secret_notes=user[6]
            ) for user in users_data
        ]

    def resolve_products(self, info, category=None, search=None):
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        if category and search:
            # Vulnerable to union-based injection
            query = f"SELECT * FROM products WHERE category = '{category}' AND name LIKE '%{search}%'"
            cursor.execute(query)
        elif category:
            query = f"SELECT * FROM products WHERE category = '{category}'"
            cursor.execute(query)
        elif search:
            query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
            cursor.execute(query)
        else:
            cursor.execute("SELECT * FROM products")
            
        products_data = cursor.fetchall()
        conn.close()
        
        return [
            ProductType(
                id=product[0],
                name=product[1],
                price=product[2],
                description=product[3],
                category=product[4],
                internal_notes=product[5]
            ) for product in products_data
        ]

    def resolve_product(self, info, id):
        # Basic IDOR - no authorization check
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ?", (id,))
        product_data = cursor.fetchone()
        conn.close()
        
        if product_data:
            return ProductType(
                id=product_data[0],
                name=product_data[1],
                price=product_data[2],
                description=product_data[3],
                category=product_data[4],
                internal_notes=product_data[5]
            )
        return None

    def resolve_orders(self, info, user_id=None):
        # No authorization check - can view any user's orders
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        if user_id:
            # Vulnerable to injection
            query = f"SELECT * FROM orders WHERE user_id = {user_id}"
            cursor.execute(query)
        else:
            cursor.execute("SELECT * FROM orders")
            
        orders_data = cursor.fetchall()
        conn.close()
        
        return [
            OrderType(
                id=order[0],
                user_id=order[1],
                product_id=order[2],
                quantity=order[3],
                total_price=order[4],
                status=order[5],
                admin_notes=order[6]
            ) for order in orders_data
        ]

    def resolve_introspection_enabled(self, info):
        return "GraphQL introspection is enabled - this should be disabled in production!"

# GraphQL Mutations
class LoginMutation(Mutation):
    class Arguments:
        username = String(required=True)
        password = String(required=True)
    
    Output = AuthPayload
    
    def mutate(self, info, username, password):
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        # Vulnerable SQL injection in authentication
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
            
            return AuthPayload(
                success="true",
                token=token,
                user=UserType(
                    id=user[0],
                    username=user[1],
                    email=user[3],
                    role=user[4]
                ),
                message="Authentication successful"
            )
        
        return AuthPayload(
            success="false",
            message="Invalid credentials",
            token=None,
            user=None
        )

class UpdateUserMutation(Mutation):
    class Arguments:
        id = Int(required=True)
        email = String()
        role = String()
    
    Output = UserType
    
    def mutate(self, info, id, email=None, role=None):
        # No authorization check - IDOR vulnerability
        conn = sqlite3.connect('vulnerable_graphql.db')
        cursor = conn.cursor()
        
        if email and role:
            # Vulnerable to injection
            query = f"UPDATE users SET email = '{email}', role = '{role}' WHERE id = {id}"
            cursor.execute(query)
        elif email:
            query = f"UPDATE users SET email = '{email}' WHERE id = {id}"
            cursor.execute(query)
        elif role:
            query = f"UPDATE users SET role = '{role}' WHERE id = {id}"
            cursor.execute(query)
            
        conn.commit()
        
        # Return updated user
        cursor.execute(f"SELECT * FROM users WHERE id = {id}")
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return UserType(
                id=user_data[0],
                username=user_data[1],
                email=user_data[3],
                role=user_data[4],
                secret_notes=user_data[6]
            )
        return None

class Mutations(ObjectType):
    login = LoginMutation.Field()
    update_user = UpdateUserMutation.Field()

# Create GraphQL Schema
schema = Schema(query=Query, mutation=Mutations)

# Add GraphQL endpoint
app.add_url_rule(
    '/graphql',
    view_func=GraphQLView.as_view('graphql', schema=schema, graphiql=True)
)

# Simple endpoint to check if API is running
@app.route('/health')
def health_check():
    return jsonify({'status': 'GraphQL API is running', 'endpoint': '/graphql'})

# Rate limiting test endpoint (still needed for business logic testing)
@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    data = request.get_json()
    email = data.get('email', '')
    # No rate limiting implemented
    return jsonify({'message': f'Password reset link sent to {email}'}), 200

# API key test endpoint
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    api_key = request.headers.get('X-API-Key')
    
    # Weak API key validation
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
