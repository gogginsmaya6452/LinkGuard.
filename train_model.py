import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
import os

# 1. Load Data
if not os.path.exists('phishing.csv'):
    print("Error: phishing.csv not found!")
    exit()

try:
    data = pd.read_csv('phishing.csv')
    print("Dataset loaded successfully.")
except Exception as e:
    print(f"Error loading CSV: {e}")
    exit()

# 2. Select ONLY URL-based Features
# We drop ID and any HTML-based features (like Iframe, Images, etc.)
# We keep only what we can calculate from the URL string in Python.
selected_features = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'IpAddress', 'HostnameLength', 'PathLength'
]

# Check if these exist in your CSV
missing = [col for col in selected_features if col not in data.columns]
if missing:
    print(f"CRITICAL ERROR: Your CSV is missing these columns: {missing}")
    print("Please check your CSV headers.")
    exit()

X = data[selected_features]
y = data['CLASS_LABEL']

# 3. Train
print("Training Model on URL Features only...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 4. Save
filename = 'website_status_model.pkl'
if os.path.exists(filename): os.remove(filename)

with open(filename, 'wb') as f:
    pickle.dump(rf_model, f)

print(f"Success! Model saved. Accuracy on test data: {rf_model.score(X_test, y_test)*100:.2f}%")