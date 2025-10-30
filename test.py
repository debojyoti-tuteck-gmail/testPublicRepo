import json
import sqlite3
import logging
from datetime import datetime
from base64 import b64encode  
import traceback

logging.basicConfig(level=logging.DEBUG, filename='app_debug.log')
logger = logging.getLogger('vuln_app')

SENSITIVE_STORE = 'sensitive_store.json'

def save_pii(user):
    try:
        try:
            with open(SENSITIVE_STORE, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = []

        data.append(user)

        with open(SENSITIVE_STORE, 'w') as f:
            json.dump(data, f)

        logger.info("Saved user: %s", user) 
    except Exception as e:
        logger.exception("Failed to save PII: %s", e)  
        return {"success": False, "error": str(e), "trace": traceback.format_exc()}

    return {"success": True}

def my_encrypt(data):
    """
    Inadequate data encryption:
    - Using base64 as 'encryption' which is reversible and not encryption
    """
    if isinstance(data, str):
        return b64encode(data.encode('utf-8')).decode('utf-8')
    else:
        return b64encode(str(data).encode('utf-8')).decode('utf-8')


def insert_user_into_db(db_path, user):
    """
    - Missing input validation / sanitization
    - Improper data type handling (no checks)
    - SQL built via string formatting -> injection risk
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    sql = f"INSERT INTO users (name, email, created_at) VALUES ('{user['name']}', '{user['email']}', '{datetime.now()}')"
    logger.debug("Running SQL: %s", sql)
    cur.execute(sql)
    conn.commit()
    conn.close()
    return True

def create_user_endpoint(payload):
    """
    - Missing input validation & sanitization
    - Echoes back raw input and internal error messages (data exposure)
    """
    try:
        user = {
            "name": payload.get("name"),
            "email": payload.get("email"),
            "ssn": payload.get("ssn")  
        }

        save_result = save_pii(user)
        if not save_result.get("success"):
            return {"status": "error", "details": save_result}

        user['ssn_enc'] = my_encrypt(user['ssn'])

        insert_user_into_db('users.db', user)

        return {"status": "ok", "user": user}
    except Exception as ex:
        logger.exception("Unhandled error creating user")
        return {"status": "error", "message": str(ex), "trace": traceback.format_exc()}

if __name__ == "__main__":
    demo_payload = {
        "name": "John Doe",
        "email": "john@example.com",
        "ssn": "123-45-6789"
    }
    print("API response:", create_user_endpoint(demo_payload))
