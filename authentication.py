





# pip install streamlit mysql-connector-python


import streamlit as st
import mysql.connector
from mysql.connector import Error
import hashlib

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to connect to the MySQL database
def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',       # e.g., 'localhost'
            user='django_user',   # e.g., 'root'
            password='user@123', # MySQL password
            database='htmlformdata'  # Database name
        )
        return connection
    except Error as e:
        st.error(f"Error: {e}")
        return None

# Function to create the users table if it doesn't exist
def create_users_table():
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            );
        ''')
        connection.commit()
        cursor.close()
        connection.close()

# Function to validate login credentials
def validate_login(username, password):
    connection = create_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        if user and user['password'] == hash_password(password):
            return True
    return False

# Function to create a new user
def create_user(username, password):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("User created successfully!")
    else:
        st.error("Failed to create user.")

# Streamlit UI for login and registration
def main():
    st.title("Login Screen")

    # Create the users table if it doesn't exist
    create_users_table()

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if validate_login(username, password):
                st.success(f"Welcome {username}!")
            else:
                st.error("Invalid Username or Password")

    elif choice == "Register":
        st.subheader("Create a new account")

        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if new_password == confirm_password:
                create_user(new_username, new_password)
            else:
                st.error("Passwords do not match")

if __name__ == '__main__':
    main()
