import streamlit as st
from flask import Flask, request, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Assume this is your authentication check
def authenticate_user(username, password):
    # Dummy check; replace with your authentication logic
    if username == "admin" and password == "password":
        return "user_id_123"
    return None

# Streamlit App Code
def login():
    st.title("Login")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        user_id = authenticate_user(username, password)
        if user_id:
            access_token = create_access_token(user_id)
            refresh_token = create_refresh_token(user_id)
            
            # Set the tokens as cookies
            response = make_response({"message": "Login successful"})
            response.set_cookie("access_token", access_token, httponly=True)
            response.set_cookie("refresh_token", refresh_token, httponly=True)
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials")

def check_authentication():
    access_token = request.cookies.get("access_token")
    if access_token:
        user_id = verify_token(access_token, SECRET_KEY)
        if user_id:
            st.session_state["authenticated"] = True
            return user_id
    
    # Check for refresh token if access token is expired or invalid
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        user_id = verify_token(refresh_token, REFRESH_SECRET_KEY)
        if user_id:
            # Issue new tokens
            new_access_token = create_access_token(user_id)
            response = make_response({"message": "Token refreshed"})
            response.set_cookie("access_token", new_access_token, httponly=True)
            st.session_state["authenticated"] = True
            return user_id
    return None

def main_app():
    st.title("Main App")
    st.write("Welcome to the protected content!")
    if st.button("Logout"):
        st.session_state["authenticated"] = False
        response = make_response({"message": "Logged out"})
        response.set_cookie("access_token", "", expires=0)
        response.set_cookie("refresh_token", "", expires=0)
        st.success("Logged out successfully!")
        st.experimental_rerun()

def main():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    
    if st.session_state["authenticated"]:
        main_app()
    else:
        user_id = check_authentication()
        if user_id:
            main_app()
        else:
            login()

if __name__ == "__main__":
    main()
