import mysql.connector
import bcrypt
from getpass import getpass
import re
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()
#connecting to database
db=mysql.connector.connect(
    host="localhost",
    user=os.environ.get('Db_user'),
    password=os.environ.get('Db_password'),
    database="access_control_1"
)

cur=db.cursor()

#Executing MySQL commands to create the database
def initialize_db():
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL
                )''' )
    
    cur.execute('''CREATE TABLE IF NOT EXISTS resources(
            id INT AUTO_INCREMENT PRIMARY KEY,
            resource_name VARCHAR(255) UNIQUE NOT NULL,
            restricted_role VARCHAR(50)
                )''' )
    
    cur.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        action VARCHAR(255) NOT NULL,
        timestamp DATETIME DEFAULT NOW()
    )''')

    cur.execute('''  CREATE TABLE if not exists failed_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

#Saving the default username and password in hash
    admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
    cur.execute('''INSERT IGNORE INTO users (username, password,email, role) 
        VALUES ('admin', %s,'admin@gmail.com', 'admin')''',(admin_password.decode('utf-8'),))
    
    cur.execute('''INSERT IGNORE INTO resources (resource_name, restricted_role)
        VALUES 
        ('Confidential Report', 'admin'),
        ('User Settings', 'manager'),
        ('Public Dashboard', NULL)''')
    
    db.commit()

#Preventing dictionary attack by refining attempts to only 3 attempts and blocked the account fot 10 mints if excceeded 
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME = timedelta(minutes=10)

def check_failed_attempts(username):
    time_window_start = datetime.now() - LOCKOUT_TIME
    # Check the number of failed attempts within the last 10 minutes
    cur.execute("SELECT COUNT(*) FROM failed_logins WHERE username=%s AND timestamp > %s", (username, time_window_start))
    failed_attempts = cur.fetchone()[0]
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        return True
    return False


def login():
    print("\tLOGIN")
    username=input("Username: ")
    password=getpass("Password: ")
    if check_failed_attempts(username):
        print("Your account is temporarily locked. Please try again later.")
        return None
    cur.execute("SELECT * FROM users where username=%s", (username,))
    user= cur.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'),user[2].encode('utf-8')):
        log_action(username,"Logged In")
        print(f"Welcome {username}  Role: {user[4]}")
        reset_failed_attempts(username)
        return {"username": user[1], "role": user[4]}
    else:
        log_action(username,"Incorrect Credentials")
        print("Invalid credentials!")
        track_failed_attempt(username)
        return None
    
def track_failed_attempt(username):
    cur.execute("INSERT INTO failed_logins (username) VALUES (%s)", (username,))
    db.commit()

#If the user has entered correct credentials. remove that from failed logins table
def reset_failed_attempts(username):
    cur.execute("DELETE FROM failed_logins WHERE username=%s", (username,))
    db.commit()

#Stored all the login actions occured.
def log_action(username, action): 
    cur.execute("INSERT INTO logs(username, action) VALUES (%s,%s)", (username,action))
    db.commit()

#isko seekhlo
def authorize(role, resource):
    cur.execute("SELECT restricted_role FROM resources WHERE resource_name=%s", (resource,))
    result = cur.fetchone()
    if result:
        restricted_role = result[0]
        if restricted_role and role != restricted_role:
            print(f"Access Denied! Only '{restricted_role}' role can access this resource.")
            return False
        else:
            print(f"Access Granted to '{resource}'!")
            return True
    else:
        print("Resource not found.")
        return False
    
def access_resources(user):
    print("\n--- Access Resources ---")
    cur.execute("SELECT resource_name FROM resources")
    resources = cur.fetchall()
    for i, resource in enumerate(resources, start=1):
        print(f"{i}. {resource[0]}")
    choice = int(input("\nSelect a resource (number): ")) - 1
    if 0 <= choice < len(resources):
        resource_name = resources[choice][0]
        if authorize(user['role'], resource_name):
            log_action(user['username'], f"Accessed resource '{resource_name}'")
    else:
        print("Invalid selection!")


def admin_menu():
    print("\n--- Admin Menu ---")
    print("1. View Logs")
    print("2. Add User")
    print("3. Add Resource")
    choice = input("Choose an option: ")

    if choice == "1":
        view_logs()
    elif choice == "2":
        add_user()
    elif choice == "3":
        add_resources()
    else:
        print("Invalid option!")

def view_logs():
    print("\tSystem Logs")
    cur.execute("Select * from logs")
    logs=cur.fetchall()
    for log in logs:
        print(F"ID: {log[0]}, User: {log[1]}, Action: {log[2]}, Timestamp: {log[3]}")

def add_resources():
    print("\n--- Add Resource ---")
    resource_name = input("Resource Name: ")
    restricted_role = input("Restricted Role (leave blank for public): ")
    try:
        cur.execute("INSERT INTO resources (resource_name, restricted_role) VALUES (%s, %s)", (resource_name, restricted_role))
        db.commit()
        print(f"Resource '{resource_name}' added successfully!")
    except mysql.connector.IntegrityError:
        print("Resource already exists!")

def add_user():
    print("\tADD USER")
    username = input("New Username: ")
    email=input("Email Address: ")
    while True:
        password = getpass("New Password: ")
        if validate_password_strength(password):
            print("Password is weak, try again.")
        else:
            #Store the hash in decoded from means in string format.
            hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    role = input("Role (admin/manager/user): ")

    try:
        cur.execute("INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)", (username, hash, email, role))
        print("User added")
    except mysql.connector.IntegrityError:
        print("Username already exists!")

def validate_password_strength(password):
    if (len(password) < 8 or 
        not re.search(r"\d", password) or 
        not re.search(r"[A-Z]", password) or 
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        print("Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character.")
        return True
    return False

def main():
    initialize_db()
    user=login()
    if user:
        while True:
            print("\n--- Main Menu ---")
            print("1. Access Resources")
            if user['role']=="admin":
                 print("2. Admin Menu")
            print("3. Logout")

            choice = input("Choose an option: ")
            if choice == "1":
                access_resources(user)
            elif choice == "2" and user['role'] == "admin":
                admin_menu()
            elif choice == "3":
                log_action(user['username'], "Logged Out")
                print("Logged out. Goodbye!")
                break
            else:
                print("Invalid option!")

if __name__ == "__main__":
    main()
