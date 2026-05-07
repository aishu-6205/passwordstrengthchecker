import re
import sqlite3
import secrets
import string
import hashlib
import math

 Initialize database

def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            hash TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn, cursor

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"

def is_reused(password, cursor):
    cursor.execute("SELECT hash FROM passwords")
    rows = cursor.fetchall()

    for (stored,) in rows:
        try:
            salt, old_hash = stored.split("$")
            new_hash = hashlib.sha256((salt + password).encode()).hexdigest()
            if new_hash == old_hash:
                return True
        except:
            continue
    return False

def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[!@#$%^&*]", password): pool += 10

    if pool == 0:
        return 0

    return round(len(password) * math.log2(pool), 2)

def check_strength(password, cursor):
    score = 0
    feedback = []

    if not password:
        return 0, ["Password cannot be empty"]

    
    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters")
    common = {"password", "123456", "qwerty", "admin", "welcome"}
    if password.lower() in common:
        feedback.append("This is a very common password")
        score = 0
    if is_reused(password, cursor):
        feedback.append("Password already used before")
        score = 0

    return score, feedback


def generate_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def save_password(password, cursor, conn):
    hashed = hash_password(password)
    cursor.execute("INSERT INTO passwords (hash) VALUES (?)", (hashed,))
    conn.commit()

def main():
    conn, cursor = init_db()

    try:
        password = input("Enter your password: ").strip()

        score, feedback = check_strength(password, cursor)
        entropy = calculate_entropy(password)

        print("\n--- RESULT ---")
        print("Score:", score, "/ 7")
        print("Entropy:", entropy, "bits")

        if feedback:
            print("\nSuggestions:")
            for f in feedback:
                print("-", f)
        else:
            print("Strong password!")

        if score < 5:
            print("\nSuggested strong password:")
            print(generate_password())

        save_password(password, cursor, conn)

    finally:
        conn.close()


if __name__ == "__main__":
    main()