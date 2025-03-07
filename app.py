from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import pandas as pd
import joblib
import validators
import re
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Load Trained Model
try:
    model = joblib.load("phishing_model.pkl")  # Ensure this file exists in the project folder
    print("✅ Model Loaded Successfully!")
except Exception as e:
    print("❌ Error loading model:", e)
    model = None

phishing_keywords = ["secure", "account", "banking", "login", "update", "verify", "password"]

# Extract Features from URL
def extract_features(url):
    url = url.lower().strip()
    url = unquote(url)
    url = re.sub(r'^https?://|^www\.', '', url)

    domain = url.split('/')[0]

    if not validators.url("https://" + url):
        return None
    
    features = {
        'URL_Length': len(url),
        'Num_Dots': url.count('.'),
        'Num_Hyphens': url.count('-'),
        'Num_Slashes': url.count('/'),
        'Contains Phishing Word': int(any(word in url for word in phishing_keywords))
    }
    return pd.DataFrame([features])

# Dummy Credentials (Modify for Database Integration)
USER_CREDENTIALS = {"admin": "password"}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
        session["user"] = username
        return redirect(url_for("main_page"))
    else:
        return render_template("index.html", error="Invalid Username or Password")

@app.route("/main_page", methods=["GET", "POST"])
def main_page():
    if "user" in session:
        return render_template("main_page.html", username=session["user"])
    else:
        return redirect(url_for("home"))

@app.route("/predict", methods=["POST"])
def predict():
    if "user" not in session:
        return redirect(url_for("home"))

    url = request.form.get("url")
    features = extract_features(url)

    if features is not None and model:
        prediction = model.predict(features)[0]
        result = "🔴 Phishing URL Detected" if prediction == 1 else "🟢 Safe URL"
    else:
        result = "⚠ Invalid URL"

    return render_template("main_page.html", username=session["user"], result=result)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

# Serve Static Files Correctly (Fixes Background Image Not Loading on Render)
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

if __name__ == "__main__":
    app.run(debug=True)