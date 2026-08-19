import os
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sklearn.preprocessing import LabelEncoder
from sklearn.cluster import KMeans
from sklearn.tree import DecisionTreeClassifier
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ==========================================
# CONFIGURATION
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'forensic_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forensic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

db = SQLAlchemy(app)

if not os.path.exists('static/plots'):
    os.makedirs('static/plots')

# ==========================================
# DATABASE MODELS
# ==========================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')

class Crime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(50), unique=True, nullable=False)
    crime_type = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    time_slot = db.Column(db.String(20))
    modus_operandi = db.Column(db.Text)
    suspects = db.relationship('Suspect', secondary='crime_suspect', back_populates='crimes')

crime_suspect = db.Table('crime_suspect',
    db.Column('crime_id', db.Integer, db.ForeignKey('crime.id'), primary_key=True),
    db.Column('suspect_id', db.Integer, db.ForeignKey('suspect.id'), primary_key=True)
)

class Suspect(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    crimes = db.relationship('Crime', secondary='crime_suspect', back_populates='suspects')

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def is_logged_in():
    return 'user_id' in session

def get_user_role():
    return session.get('role', None)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        if get_user_role() != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# ROUTES - AUTHENTICATION
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Account created! Username: {username}, Role: {role}', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/setup')
def setup():
    """Create default accounts - only runs if they don't exist"""
    with app.app_context():
        # This won't affect your existing data!
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin123'), role='admin')
            db.session.add(admin)
        
        if not User.query.filter_by(username='user').first():
            user = User(username='user', password=generate_password_hash('user123'), role='user')
            db.session.add(user)
        
        db.session.commit()
    
    flash('Setup complete! Login with admin/admin123 or user/user123', 'success')
    return redirect(url_for('login'))

# ==========================================
# USER MANAGEMENT
# ==========================================

@app.route('/manage_users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('manage_users'))
    
    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:id>')
@admin_required
def delete_user(id):
    user = User.query.get(id)
    if user:
        if user.username == 'admin':
            flash('Cannot delete main admin', 'danger')
        else:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted', 'success')
    return redirect(url_for('manage_users'))

# ==========================================
# MAIN PAGES
# ==========================================

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    crimes = Crime.query.all()
    suspects = Suspect.query.all()
    return render_template('dashboard.html', crimes=crimes, suspects=suspects, 
                           count=len(crimes), suspect_count=len(suspects))

@app.route('/add_crime', methods=['GET', 'POST'])
@admin_required
def add_crime():
    suspects = Suspect.query.all()
    if request.method == 'POST':
        case_id = request.form['case_id']
        
        if Crime.query.filter_by(case_id=case_id).first():
            flash('Case ID already exists!', 'danger')
            return redirect(url_for('add_crime'))
        
        c_type = request.form['crime_type']
        loc = request.form['location']
        date = request.form['date']
        time = request.form['time_slot']
        mo = request.form['modus_operandi']
        
        date_obj = datetime.strptime(date, '%Y-%m-%d')
        new_crime = Crime(case_id=case_id, crime_type=c_type, location=loc, 
                          date=date_obj, time_slot=time, modus_operandi=mo)
        
        selected_suspects = request.form.getlist('suspects')
        for sus_id in selected_suspects:
            suspect = Suspect.query.get(int(sus_id))
            if suspect:
                new_crime.suspects.append(suspect)
        
        db.session.add(new_crime)
        db.session.commit()
        flash("Crime Record Added!", "success")
        return redirect(url_for('dashboard'))
    return render_template('add_crime.html', suspects=suspects)

@app.route('/add_suspect', methods=['GET', 'POST'])
@admin_required
def add_suspect():
    if request.method == 'POST':
        name = request.form['name']
        desc = request.form['desc']
        sus = Suspect(name=name, description=desc)
        db.session.add(sus)
        db.session.commit()
        flash("Suspect Registered!", "success")
        return redirect(url_for('dashboard'))
    return render_template('add_suspect.html')

@app.route('/view_suspects')
@login_required
def view_suspects():
    suspects = Suspect.query.all()
    return render_template('view_suspects.html', suspects=suspects)

@app.route('/delete_crime/<int:id>')
@admin_required
def delete_crime(id):
    crime = Crime.query.get(id)
    if crime:
        db.session.delete(crime)
        db.session.commit()
        flash('Crime deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_suspect/<int:id>')
@admin_required
def delete_suspect(id):
    suspect = Suspect.query.get(id)
    if suspect:
        db.session.delete(suspect)
        db.session.commit()
        flash('Suspect deleted!', 'success')
    return redirect(url_for('view_suspects'))

@app.route('/clear_all_data')
@admin_required
def clear_all_data():
    try:
        db.session.query(crime_suspect).delete()
        Crime.query.delete()
        Suspect.query.delete()
        db.session.commit()
        flash('All data cleared!', 'success')
    except:
        db.session.rollback()
    return redirect(url_for('dashboard'))

# ==========================================
# ANALYSIS - VISUALIZATION & ML
# ==========================================

@app.route('/analysis')
@login_required
def analysis():
    crimes = Crime.query.all()
    data = []
    for c in crimes:
        data.append({
            'type': c.crime_type, 
            'loc': c.location, 
            'date': c.date, 
            'hour': c.date.hour, 
            'time': c.time_slot
        })
    df = pd.DataFrame(data)
    
    predicted_crime = "No Data"
    
    if not df.empty:
        # 1. Bar Chart - Crime Types
        plt.figure(figsize=(10, 6))
        ax = sns.countplot(data=df, x='type', palette='viridis')
        plt.title("Crime Types Frequency", fontsize=16)
        plt.xlabel("Crime Type", fontsize=12)
        plt.ylabel("Count", fontsize=12)
        for container in ax.containers:
            ax.bar_label(container)
        plt.tight_layout()
        plt.savefig('static/plots/barchart.png')
        plt.close()
        
        # 2. Timeline - Crime Trend
        df['date'] = pd.to_datetime(df['date'])
        timeline = df.groupby(df['date'].dt.date).size()
        plt.figure(figsize=(12, 6))
        plt.plot(timeline.index, timeline.values, marker='o', color='red', linewidth=2, markersize=8)
        plt.title("Crime Trend Over Time", fontsize=16)
        plt.xlabel("Date", fontsize=12)
        plt.ylabel("Number of Crimes", fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('static/plots/timeline.png')
        plt.close()
        
        # 3. Heatmap - Location vs Crime Type
        plt.figure(figsize=(12, 6))
        heatmap_data = pd.crosstab(df['type'], df['loc'])
        sns.heatmap(heatmap_data, annot=True, cmap='YlOrRd', fmt='d', linewidths=0.5)
        plt.title("Crime Heatmap (Type vs Location)", fontsize=16)
        plt.xlabel("Location", fontsize=12)
        plt.ylabel("Crime Type", fontsize=12)
        plt.tight_layout()
        plt.savefig('static/plots/heatmap.png')
        plt.close()
        
        # 4. Pie Chart - Time Slots
        plt.figure(figsize=(10, 10))
        time_counts = df['time'].value_counts()
        colors = sns.color_palette('pastel')
        plt.pie(time_counts, labels=time_counts.index, autopct='%1.1f%%', 
                colors=colors, startangle=90, explode=[0.05]*len(time_counts))
        plt.title("Crimes by Time of Day", fontsize=16)
        plt.tight_layout()
        plt.savefig('static/plots/piechart.png')
        plt.close()
        
        # 5. K-Means Clustering - Improved
        le_loc = LabelEncoder()
        df['loc_encoded'] = le_loc.fit_transform(df['loc'])
        
        X = df[['loc_encoded', 'hour']].values
        kmeans = KMeans(n_clusters=3, n_init=10, random_state=42)
        df['cluster'] = kmeans.fit_predict(X)
        
        plt.figure(figsize=(14, 8))
        
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1']
        cluster_labels = ['Cluster 1: Night Crimes', 'Cluster 2: Day Crimes', 'Cluster 3: Evening Crimes']
        
        for i in range(3):
            cluster_data = df[df['cluster'] == i]
            plt.scatter(cluster_data['loc'], cluster_data['hour'], 
                       c=colors[i], label=cluster_labels[i], 
                       s=200, alpha=0.7, edgecolors='black', linewidths=1)
        
        plt.title("Crime Hotspots - K-Means Clustering", fontsize=18, fontweight='bold')
        plt.xlabel("Location", fontsize=14)
        plt.ylabel("Hour of Crime (0-23)", fontsize=14)
        plt.xticks(rotation=45, fontsize=12)
        plt.yticks(range(0, 24, 2), fontsize=10)
        plt.legend(fontsize=12, loc='upper right')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('static/plots/cluster.png')
        plt.close()
        
        # 6. Decision Tree Prediction
        le_crime = LabelEncoder()
        days = {'Monday':0, 'Tuesday':1, 'Wednesday':2, 'Thursday':3, 'Friday':4, 'Saturday':5, 'Sunday':6}
        df['day_num'] = df['date'].dt.day_name().map(days)
        
        X = df[['loc_encoded', 'day_num']].fillna(0).values
        y = le_crime.fit_transform(df['type'])
        
        clf = DecisionTreeClassifier(random_state=42)
        clf.fit(X, y)
        pred = clf.predict([[0, 4]])  # Downtown, Friday
        predicted_crime = le_crime.inverse_transform(pred)[0]

    return render_template('analysis.html', prediction=predicted_crime)

# ==========================================
# MAIN
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)