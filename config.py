# config.py
import os

# Define o diretório base do projeto como o diretório onde este arquivo config.py está localizado.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_FILE = os.path.join(BASE_DIR, "entradas_web.db") # Path to database file
TABLE_PRODUTOS_ETRADE = 'produtos_etrade'
TABLE_PRODUTOS_ETRADE_STAGING = 'produtos_etrade_staging'
TABLE_PRODUTOS_VENDIDOS_LOG = 'produtos_vendidos_log'
TABLE_USUARIOS = 'usuarios'
TABLE_LOG_ENTRADAS_PRATELEIRA = 'log_entradas_prateleira'
TABLE_LOTES_PRODUTOS = 'lotes_produtos'
TABLE_LOG_AJUSTES_ESTOQUE = 'log_ajustes_estoque'
TABLE_FEEDBACK = 'feedback' # Adicionado para uso futuro
TABLE_AUDIT_LOG = 'log_auditoria'
TABLE_PRICE_HISTORY = 'historico_precos'
TABLE_NOTIFICATIONS = 'notificacoes'
TABLE_SETTINGS = 'configuracoes_sistema'
TABLE_ANOTACOES = 'anotacoes' # Nova tabela para anotações
TABLE_STOCK_CORRECTION_LOG = 'log_correcao_estoque'
TABLE_LOST_SALES_LOG = 'log_vendas_perdidas'

TABLE_LOG_PRODUCAO = 'log_producao' # Nova tabela para log de produção

# --- Sales Analysis Configuration ---
TOP_SELLING_DAYS = 30  # Period (in days) for recent sales consideration
TOP_SELLING_COUNT = 20 # Number of top selling products to consider
SALES_ANALYSIS_PERIOD_DAYS = 30 # Default period for "Days of Stock Remaining" calculation

# --- Email Configuration (for notifications) ---
EMAIL_SENDER = os.environ.get('EMAIL_SENDER') # Lê da variável de ambiente
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD') # Lê da variável de ambiente
EMAIL_RECEIVER = os.environ.get('EMAIL_RECEIVER') # Lê da variável de ambiente
SMTP_SERVER = 'smtp.gmail.com' # Ex: 'smtp.gmail.com' para Gmail
SMTP_PORT = 587 # Porta padrão para TLS/STARTTLS

# --- Ngrok Configuration ---
# Deixe em branco ou "" se não quiser usar um domínio estático.
NGROK_STATIC_DOMAIN = "inspired-causal-griffon.ngrok-free.app"
