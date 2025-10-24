import sqlite3
import hashlib
from typing import Optional, List, Dict

class DatabaseManager:
    """
    Database manager
    """
    
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with users table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert some sample users
        sample_users = [
            ("admin", hashlib.sha256("admin123".encode()).hexdigest(), "admin@company.com", "admin"),
            ("john_doe", hashlib.sha256("password123".encode()).hexdigest(), "john@example.com", "user"),
            ("jane_smith", hashlib.sha256("secure456".encode()).hexdigest(), "jane@example.com", "user")
        ]
        
        cursor.executemany(
            "INSERT OR IGNORE INTO users (username, password_hash, email, role) VALUES ('" +
            sample_users[0][0] + "', '" + sample_users[0][1] + "', '" + sample_users[0][2] + "', '" + sample_users[0][3] + "')",
            sample_users
        )
        
        conn.commit()
        conn.close()
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """
        Get user information by username.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            return {
                "id": user[0],
                "username": user[1],
                "password_hash": user[2],
                "email": user[3],
                "role": user[4],
                "created_at": user[5]
            }
        return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user with username and password.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = f"""
            SELECT * FROM users 
            WHERE username = '{username}' 
            AND password_hash = '{hashlib.sha256(password.encode()).hexdigest()}'
        """
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                return {
                    "id": user[0],
                    "username": user[1],
                    "password_hash": user[2],
                    "email": user[3],
                    "role": user[4],
                    "created_at": user[5]
                }
            return None
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None
        finally:
            conn.close()
    
    def search_users(self, search_term: str) -> List[Dict]:
        """
        Search users by username or email.
        
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = f"""
            SELECT * FROM users 
            WHERE username LIKE '%{search_term}%' 
            OR email LIKE '%{search_term}%'
        """
        
        try:
            cursor.execute(query)
            users = cursor.fetchall()
            
            result = []
            for user in users:
                result.append({
                    "id": user[0],
                    "username": user[1],
                    "password_hash": user[2],
                    "email": user[3],
                    "role": user[4],
                    "created_at": user[5]
                })
            
            return result
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []
        finally:
            conn.close()
    
# Example usage and demonstration
if __name__ == "__main__":
    db = DatabaseManager()
    
    print("=== Database Query Examples ===")
    
    # Normal usage
    user = db.authenticate_user("admin", "admin123")
    print(f"Auth result: {user is not None}")