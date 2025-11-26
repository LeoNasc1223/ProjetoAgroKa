import sqlite3
import logging
import datetime
from flask import session
from config import DATABASE_FILE, TABLE_AUDIT_LOG

logger = logging.getLogger(__name__)

def log_audit(action, details, user_id=None, username=None):
    """Registra uma ação no log de auditoria."""
    try:
        # Se o usuário estiver logado, pega os dados da sessão
        if 'user_id' in session:
            user_id = session.get('user_id')
            username = session.get('username')
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(f"""
            INSERT INTO {TABLE_AUDIT_LOG} (timestamp, user_id, username, action, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp_now, user_id, username, action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Falha ao registrar log de auditoria: {e}", exc_info=True)

