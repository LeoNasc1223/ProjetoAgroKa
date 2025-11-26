from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for, flash, make_response
import sqlite3
import logging
import re # Adicionado para expressões regulares
import os
import subprocess # Módulo para executar processos externos
import psutil # Para verificar processos em execução
import sys # Para obter o caminho do executável Python
import time # Para adicionar pausas
import requests # Para consultar a API do ngrok
from werkzeug.security import generate_password_hash, check_password_hash
import secrets # Para gerar uma secret key segura
from functools import wraps # Para o decorador
import io
import csv
import smtplib
import ssl
from email.message import EmailMessage
# ... outros imports
import unicodedata
import datetime
from collections import deque

# Importar configurações e funções de outros módulos
from config import DATABASE_FILE, TABLE_PRODUTOS_ETRADE, TABLE_PRODUTOS_ETRADE_STAGING, TABLE_USUARIOS, TABLE_LOG_ENTRADAS_PRATELEIRA, TABLE_PRODUTOS_VENDIDOS_LOG, TABLE_LOTES_PRODUTOS, TABLE_LOG_AJUSTES_ESTOQUE, TABLE_FEEDBACK, TABLE_AUDIT_LOG, TABLE_PRICE_HISTORY, TABLE_SETTINGS, TABLE_NOTIFICATIONS, EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER, SMTP_SERVER, SMTP_PORT, TABLE_ANOTACOES, TABLE_STOCK_CORRECTION_LOG, TABLE_LOST_SALES_LOG, TABLE_LOG_PRODUCAO, NGROK_STATIC_DOMAIN
from main_logic import processar_entrada_unica, calculate_days_of_stock_remaining, SALES_ANALYSIS_PERIOD_DAYS
from utils import log_audit # Importa a função de log do módulo de utilitários

app = Flask(__name__)

# Habilita a extensão 'do' no Jinja2, permitindo o uso de {% do ... %} nos templates.
app.jinja_env.add_extension('jinja2.ext.do')

# --- Fila de Tarefas para o Agente ---
# Dummy constants for demonstration mode, as Google Sheets integration is disabled.
ABA_REPOSICAO = "DEMO_REPOSICAO_LOJA1"
ABA_REPOSICAO_LOJA2 = "DEMO_REPOSICAO_LOJA2"
ABA_COMPRAS = "DEMO_COMPRAS"
ABA_PRODUCAO = "DEMO_PRODUCAO"

AUTOMATION_TASK_QUEUE = deque(maxlen=10) # Fila para armazenar tarefas para o agente. Maxlen evita que a fila cresça indefinidamente.

# Configuração da Chave Secreta para Sessões
# IMPORTANTE: Mantenha esta chave em segredo em um ambiente de produção!
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16)) # Boa prática: usar variável de ambiente

# Configuração de logging para melhor depuração
logging.basicConfig(level=logging.INFO)
logger_app = logging.getLogger(__name__)  # Logger específico para o app Flask


def remove_accents(input_str):
    """Remove acentos de uma string, retornando uma versão ASCII."""  
    if not isinstance(input_str, str):
        return input_str
    nfkd_form = unicodedata.normalize('NFKD', input_str)
    return "".join([c for c in nfkd_form if not unicodedata.combining(c)])



# --- Lógica de Automação Local ---
ETRADE_PROCESS_NAME = "ETrade.exe"

def is_etrade_running():
    """Verifica se o processo do etrade está em execução na máquina local."""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == ETRADE_PROCESS_NAME.lower():
            return True
    return False

@app.context_processor
def inject_current_year():
    """Injeta o ano atual em todos os templates."""
    return {'current_year': datetime.date.today().year}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def create_notification(user_id, message, type='info', link=None):
    """Cria uma notificação para um usuário específico."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(f"""
            INSERT INTO {TABLE_NOTIFICATIONS} (timestamp, user_id, message, type, link, is_read)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp_now, user_id, message, type, link, 0)) # 0 = não lida
        conn.commit()
        conn.close()
        logger_app.info(f"Notificação criada para user_id {user_id}: {message}")
    except Exception as e:
        logger_app.error(f"Falha ao criar notificação para user_id {user_id}: {e}", exc_info=True)

def send_email_notification(subject, body):
    """Envia uma notificação por email para o administrador."""
    if not all([EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER, SMTP_SERVER, SMTP_PORT]):
        logger_app.warning("Configurações de e-mail incompletas. Notificação por e-mail desativada.")
        return False

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        logger_app.info(f"E-mail de notificação enviado: '{subject}'")
        return True
    except Exception as e:
        logger_app.error(f"Erro ao enviar e-mail de notificação: {e}", exc_info=True)
        return False
    
@app.route('/product/<codigo_produto>')
@login_required
def product_detail(codigo_produto):
    """
    Exibe uma página de detalhes para um produto específico, incluindo
    KPIs, histórico de vendas e lotes em estoque.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Busca o produto no banco de dados.
        cursor.execute(f"SELECT * FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto,))
        product = cursor.fetchone()
        if not product:
            flash('Produto não encontrado.', 'danger')
            conn.close()
            return redirect(url_for('global_search'))

        # Define o período de análise de vendas
        sales_period_days = 30
        start_date_dt = datetime.datetime.now() - datetime.timedelta(days=sales_period_days)
        start_date_str = start_date_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Busca o histórico de vendas do produto no período
        cursor.execute(f"""
            SELECT * FROM {TABLE_PRODUTOS_VENDIDOS_LOG}
            WHERE codigo_produto = ? AND data_verificacao >= ? AND status = 'processado'
            ORDER BY data_verificacao ASC
        """, (codigo_produto, start_date_str))
        sales_history = cursor.fetchall()

        # Calcula os "dias de estoque" restantes
        total_sales = sum(sale['quantidade_vendida'] for sale in sales_history)
        days_of_stock = 'N/A'
        if product['estoque_sistema'] is not None and product['estoque_sistema'] > 0:
            if total_sales > 0:
                average_daily_sales = total_sales / sales_period_days
                if average_daily_sales > 0:
                    days_of_stock = round(product['estoque_sistema'] / average_daily_sales)
            else:
                days_of_stock = 'Infinito'

        # Busca os lotes associados a este produto que ainda têm quantidade em estoque
        cursor.execute(f"SELECT * FROM {TABLE_LOTES_PRODUTOS} WHERE codigo_produto = ? AND quantidade > 0 ORDER BY data_validade ASC", (codigo_produto,))
        lotes_em_estoque_raw = cursor.fetchall()
        
        # Calcula os dias restantes para a validade de cada lote
        today = datetime.date.today()
        lotes_em_estoque = []
        for lote_raw in lotes_em_estoque_raw:
            lote = dict(lote_raw)
            if lote.get('data_validade'):
                try:
                    validade_date = datetime.datetime.strptime(lote['data_validade'], '%Y-%m-%d').date()
                    lote['dias_restantes'] = (validade_date - today).days
                except (ValueError, TypeError):
                    lote['dias_restantes'] = None
            else:
                lote['dias_restantes'] = None
            lotes_em_estoque.append(lote)

        conn.close()

        return render_template('product_detail.html', product=product, sales_history=sales_history, days_of_stock=days_of_stock, sales_period_days=sales_period_days, lotes=lotes_em_estoque)
    except Exception as e:
        logger_app.error(f"Erro ao carregar detalhes do produto {codigo_produto}: {e}", exc_info=True)
        flash(f"Erro ao carregar detalhes do produto: {e}", 'danger')
        return redirect(url_for('global_search'))

# --- Rotas de Autenticação (Movidas de auth.py) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Nome de usuário e senha são obrigatórios.', 'error')
            return render_template('login.html')

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, password_hash, nome_completo, cargo, loja, nome_planilha, acesso_multiloja FROM {TABLE_USUARIOS} WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password): # user[2] é password_hash
            session.clear() # Limpa qualquer sessão antiga
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['nome_completo'] = user[3]
            session['cargo'] = user[4]
            session['nome_compras'] = user[5] # Adiciona nome para compras à sessão
            session['loja'] = user[5] 
            session['nome_planilha'] = user[6] # Adiciona o nome da planilha
            session['acesso_multiloja'] = user[7] # Adiciona a permissão de multiloja
            logger_app.info(f"Usuário '{username}' logado com sucesso.")
            log_audit('login_success', f"Login bem-sucedido do usuário '{username}'")
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            log_audit('login_failed', f"Tentativa de login falhou para o usuário '{username}'", username=username)
            flash('Nome de usuário ou senha inválidos.', 'error')
            logger_app.warning(f"Tentativa de login falhou para o usuário '{username}'.")

    if 'user_id' in session:
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Desconhecido')
    log_audit('logout', f"Logout do usuário '{username}'")
    session.clear()
    flash('Você foi desconectado com sucesso.', 'success')
    logger_app.info(f"Usuário '{username}' desconectado.")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        nome_completo = request.form.get('nome_completo')
        cargo = request.form.get('cargo')
        loja = request.form.get('loja') 
        
        if not all([username, password, confirm_password, nome_completo, cargo, loja]):
            flash('Todos os campos são obrigatórios.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return render_template('register.html')
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute(f"INSERT INTO {TABLE_USUARIOS} (username, password_hash, nome_completo, cargo, loja, nome_planilha, acesso_multiloja) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, hashed_password, nome_completo, cargo, loja, username, 0))
        conn.commit()
        conn.close()
        flash('Cadastro realizado com sucesso! Você já pode fazer login.', 'success')
        logger_app.info(f"Novo usuário '{username}' cadastrado com sucesso.")
        return redirect(url_for('login'))

    return render_template('register.html')

# --- Inicialização e Migração do Banco de Dados ---

def migrate_database(cursor):
    """Verifica e aplica alterações de schema no banco de dados existente para evitar erros."""
    try:
        # Verifica as colunas da tabela de logs de entrada
        cursor.execute(f"PRAGMA table_info({TABLE_LOG_ENTRADAS_PRATELEIRA})")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'estoque_sistema_no_momento' not in columns:
            cursor.execute(f"ALTER TABLE {TABLE_LOG_ENTRADAS_PRATELEIRA} ADD COLUMN estoque_sistema_no_momento INTEGER")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'estoque_sistema_no_momento' à tabela '{TABLE_LOG_ENTRADAS_PRATELEIRA}'.")
            
        if 'backstock_calculado' not in columns:
            cursor.execute(f"ALTER TABLE {TABLE_LOG_ENTRADAS_PRATELEIRA} ADD COLUMN backstock_calculado INTEGER")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'backstock_calculado' à tabela '{TABLE_LOG_ENTRADAS_PRATELEIRA}'.")

        # Verifica a coluna 'loja' na tabela de usuários
        cursor.execute(f"PRAGMA table_info({TABLE_USUARIOS})")
        user_columns = [row[1] for row in cursor.fetchall()]
        if 'loja' not in user_columns:
            cursor.execute(f"ALTER TABLE {TABLE_USUARIOS} ADD COLUMN loja TEXT DEFAULT 'LOJA 1'")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'loja' à tabela '{TABLE_USUARIOS}'.")
        
        if 'nome_planilha' not in user_columns:
            cursor.execute(f"ALTER TABLE {TABLE_USUARIOS} ADD COLUMN nome_planilha TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'nome_planilha' à tabela '{TABLE_USUARIOS}'.")
        
        if 'acesso_multiloja' not in user_columns:
            cursor.execute(f"ALTER TABLE {TABLE_USUARIOS} ADD COLUMN acesso_multiloja INTEGER DEFAULT 0")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'acesso_multiloja' à tabela '{TABLE_USUARIOS}'.")

        # Verifica as colunas da tabela de feedback
        cursor.execute(f"PRAGMA table_info({TABLE_FEEDBACK})")
        feedback_columns = [row[1] for row in cursor.fetchall()]
        if 'admin_response' not in feedback_columns:
            cursor.execute(f"ALTER TABLE {TABLE_FEEDBACK} ADD COLUMN admin_response TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'admin_response' à tabela '{TABLE_FEEDBACK}'.")
        if 'response_timestamp' not in feedback_columns:
            cursor.execute(f"ALTER TABLE {TABLE_FEEDBACK} ADD COLUMN response_timestamp TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'response_timestamp' à tabela '{TABLE_FEEDBACK}'.")
        if 'response_user_id' not in feedback_columns:
            cursor.execute(f"ALTER TABLE {TABLE_FEEDBACK} ADD COLUMN response_user_id INTEGER")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'response_user_id' à tabela '{TABLE_FEEDBACK}'.")
        if 'response_username' not in feedback_columns:
            cursor.execute(f"ALTER TABLE {TABLE_FEEDBACK} ADD COLUMN response_username TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'response_username' à tabela '{TABLE_FEEDBACK}'.")

        # Verifica as colunas da tabela de produtos E-Trade
        cursor.execute(f"PRAGMA table_info({TABLE_PRODUTOS_ETRADE})")
        etrade_columns = [row[1] for row in cursor.fetchall()]
        if 'un_vnd' not in etrade_columns:
            cursor.execute(f"ALTER TABLE {TABLE_PRODUTOS_ETRADE} ADD COLUMN un_vnd TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'un_vnd' à tabela '{TABLE_PRODUTOS_ETRADE}'.")
        if 'subclasse' not in etrade_columns:
            cursor.execute(f"ALTER TABLE {TABLE_PRODUTOS_ETRADE} ADD COLUMN subclasse TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'subclasse' à tabela '{TABLE_PRODUTOS_ETRADE}'.")
        if 'ultima_atualizacao_etrade' not in etrade_columns:
            cursor.execute(f"ALTER TABLE {TABLE_PRODUTOS_ETRADE} ADD COLUMN ultima_atualizacao_etrade TEXT")
            logger_app.info(f"MIGRAÇÃO: Adicionada coluna 'ultima_atualizacao_etrade' à tabela '{TABLE_PRODUTOS_ETRADE}'.")


    except sqlite3.OperationalError as e:
        # Isso pode acontecer se a tabela ainda não existir, o que é normal.
        # A instrução CREATE TABLE cuidará disso.
        logger_app.info(f"Verificação de migração pulada para '{TABLE_LOG_ENTRADAS_PRATELEIRA}', provavelmente porque a tabela ainda não existe: {e}")
    except Exception as e:
        logger_app.error(f"Ocorreu um erro inesperado durante a migração do banco de dados: {e}", exc_info=True)
 
# Função para inicializar o banco de dados de usuários
def init_user_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    # Executa a migração primeiro para garantir que tabelas existentes estejam atualizadas
    migrate_database(cursor)

    # Em seguida, executa CREATE TABLE IF NOT EXISTS para criar tabelas que não existem
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_USUARIOS} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            nome_completo TEXT,
            cargo TEXT,
            loja TEXT,
            nome_planilha TEXT,
            acesso_multiloja INTEGER DEFAULT 0
        )
    ''') # Adicionar a criação da nova tabela de log aqui
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_PRODUTOS_VENDIDOS_LOG} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_produto TEXT NOT NULL,
            nome_produto TEXT,
            estoque_anterior INTEGER,
            estoque_novo INTEGER,
            quantidade_vendida INTEGER,
            data_verificacao TEXT NOT NULL,
            status TEXT NOT NULL -- 'pendente', 'processado'
        )
    ''')
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_LOG_ENTRADAS_PRATELEIRA} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            codigo_produto TEXT NOT NULL,
            nome_produto_informado TEXT,
            estoque_sistema_no_momento INTEGER,
            qtd_prateleira_informada INTEGER NOT NULL,
            qtd_cabe_informada INTEGER NOT NULL,
            backstock_calculado INTEGER,
            usuario_id INTEGER,
            usuario_username TEXT,
            FOREIGN KEY (usuario_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')

        # Tabela de Produtos E-Trade (se ainda não existir)
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_PRODUTOS_ETRADE} (
            codigo_produto TEXT PRIMARY KEY,
            nome_produto TEXT,
            un_vnd TEXT,
            preco REAL,
            estoque_sistema INTEGER,
            codigo_ean TEXT,
            marca TEXT,
            classe TEXT,
            subclasse TEXT,
            ultima_atualizacao_etrade TEXT
        )
    ''')
    # Cria uma tabela de staging com a mesma estrutura para importação segura
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_PRODUTOS_ETRADE_STAGING} (
            codigo_produto TEXT PRIMARY KEY, nome_produto TEXT, un_vnd TEXT,
            preco REAL, estoque_sistema INTEGER, codigo_ean TEXT,
            marca TEXT, classe TEXT, subclasse TEXT, ultima_atualizacao_etrade TEXT
        )
    ''')

    # Tabela para histórico de preços
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_PRICE_HISTORY} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            codigo_produto TEXT NOT NULL,
            nome_produto TEXT,
            preco_anterior REAL,
            preco_novo REAL,
            usuario_id INTEGER,
            usuario_username TEXT
        )
    ''')
 # Tabela para notificações internas
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_NOTIFICATIONS} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info', -- 'info', 'success', 'warning', 'error'
            link TEXT,
            is_read INTEGER DEFAULT 0 -- 0 for unread, 1 for read
        )
    ''')

    # Tabela para configurações do sistema
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_SETTINGS} (
            setting_name TEXT PRIMARY KEY,
            setting_value TEXT
        )
    ''')
    # Inicializa a configuração SALES_ANALYSIS_PERIOD_DAYS se não existir
    cursor.execute(f"INSERT OR IGNORE INTO {TABLE_SETTINGS} (setting_name, setting_value) VALUES (?, ?)",
                   ('SALES_ANALYSIS_PERIOD_DAYS', str(SALES_ANALYSIS_PERIOD_DAYS)))

    # Tabela para anotações
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_ANOTACOES} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            codigo_produto TEXT NOT NULL,
            nome_produto TEXT,
            anotacao TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')

    # Adicionando a tabela de feedback para uso futuro
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_FEEDBACK} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            feedback_type TEXT NOT NULL, -- 'problema', 'sugestao', 'outro'
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pendente', -- 'pendente', 'em_analise', 'resolvido', 'rejeitado'
            admin_response TEXT,
            response_timestamp TEXT,
            response_user_id INTEGER,
            response_username TEXT,
            FOREIGN KEY (user_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')
    # Adicionando a nova tabela de log de auditoria
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_AUDIT_LOG} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT
        )
    ''')
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_LOG_AJUSTES_ESTOQUE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            codigo_produto TEXT NOT NULL,
            nome_produto TEXT,
            estoque_anterior INTEGER,
            estoque_novo INTEGER,
            motivo TEXT,
            usuario_id INTEGER,
            usuario_username TEXT,
            FOREIGN KEY (usuario_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')
    # Adicionando a tabela de lotes de produtos
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_LOTES_PRODUTOS} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_produto TEXT NOT NULL,
            numero_lote TEXT,
            quantidade INTEGER NOT NULL,
            data_entrada TEXT,
            data_validade TEXT,
            usuario_id INTEGER,
            usuario_username TEXT,
            FOREIGN KEY (codigo_produto) REFERENCES {TABLE_PRODUTOS_ETRADE}(codigo_produto),
            FOREIGN KEY (usuario_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')
    # Adicionando a tabela de correção de estoque
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_STOCK_CORRECTION_LOG} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT,
            codigo_produto TEXT NOT NULL,
            nome_produto TEXT,
            estoque_sistema_registrado INTEGER,
            qtd_prateleira_contada INTEGER NOT NULL,
            qtd_estoque_contado INTEGER NOT NULL,
            total_contado INTEGER,
            diferenca INTEGER,
            status TEXT DEFAULT 'pendente' -- 'pendente', 'resolvido'
        )
    ''')
    # Adicionando a tabela de log de vendas perdidas
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_LOST_SALES_LOG} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            loja TEXT,
            produto_interesse TEXT NOT NULL,
            motivo TEXT NOT NULL,
            contato_cliente TEXT
        )
    ''')
    # Adicionando a nova tabela de log de produção
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {TABLE_LOG_PRODUCAO} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            codigo_produto_fracionado TEXT NOT NULL,
            nome_produto_fracionado TEXT,
            codigo_produto_origem TEXT NOT NULL,
            nome_produto_origem TEXT,
            qtd_prateleira_informada INTEGER,
            qtd_produzida_calculada INTEGER,
            usuario_id INTEGER,
            usuario_username TEXT,
            loja TEXT,
            status_planilha TEXT,
            FOREIGN KEY (usuario_id) REFERENCES {TABLE_USUARIOS}(id)
        )
    ''')

    # Cria o usuário 'Adm' se não existir (senha: 122312)
    try:
        cursor.execute(f"SELECT * FROM {TABLE_USUARIOS} WHERE username = ?", ('Adm',))
        if not cursor.fetchone():
            hashed_password = generate_password_hash('122312', method='pbkdf2:sha256')
            cursor.execute(f'''
                INSERT INTO {TABLE_USUARIOS} (username, password_hash, nome_completo, cargo, loja, nome_planilha, acesso_multiloja)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('Adm', hashed_password, 'Administrador', 'Admin', 'LOJA 1', 'Adm', 1))
            logger_app.info("Usuário 'Adm' criado com sucesso.")
    except sqlite3.IntegrityError:
        logger_app.info("Usuário 'Adm' já existe.")
    except Exception as e:
        logger_app.error(f"Erro ao tentar criar usuário 'Adm': {e}")
    
    conn.commit()
    conn.close()
    logger_app.info(f"Tabelas '{TABLE_USUARIOS}', '{TABLE_LOG_ENTRADAS_PRATELEIRA}', '{TABLE_PRODUTOS_VENDIDOS_LOG}', '{TABLE_LOG_AJUSTES_ESTOQUE}', '{TABLE_FEEDBACK}', '{TABLE_AUDIT_LOG}', '{TABLE_PRICE_HISTORY}', '{TABLE_SETTINGS}', '{TABLE_PRODUTOS_ETRADE}', '{TABLE_NOTIFICATIONS}', '{TABLE_ANOTACOES}', '{TABLE_STOCK_CORRECTION_LOG}', '{TABLE_LOST_SALES_LOG}' e '{TABLE_LOG_PRODUCAO}' verificadas/criadas no banco '{DATABASE_FILE}'.")

# Chame init_user_db() uma vez quando o app iniciar, antes da primeira requisição.
@app.before_request
def ensure_user_db_initialized():
    # Esta flag evita que init_user_db seja chamado em cada request, apenas na primeira.
    if not hasattr(app, '_user_db_initialized'):
        init_user_db()
        app._user_db_initialized = True

@app.route('/', methods=['GET', 'POST'])
@login_required # Protege a rota principal
def index():
    if request.method == 'POST':
        try:
            codigo = request.form.get('codigo_produto')
            nome_produto = request.form.get('nome_produto') 
            qtd_prateleira_str = request.form.get('qtd_prateleira')
            qtd_para_abastecer_str = request.form.get('qtd_para_abastecer')
            forcar_compra = 'forcar_compra' in request.form # Verifica se o modal foi confirmado
            marcar_invertido = bool(request.form.get('marcar_invertido'))

            if not all([codigo, nome_produto, qtd_prateleira_str, qtd_para_abastecer_str]):
                raise ValueError("Todos os campos são obrigatórios!")

            qtd_prateleira = int(qtd_prateleira_str)
            qtd_para_abastecer = int(qtd_para_abastecer_str)
            # Calcula a capacidade total com base na nova lógica do formulário
            qtd_cabe = qtd_prateleira + qtd_para_abastecer

            # --- Etapa Adicional: Buscar estoque do sistema para enriquecer o log ---
            estoque_sistema_atual = 0
            backstock_calculado = 0
            try:
                with sqlite3.connect(DATABASE_FILE) as conn_lookup:
                    cursor_lookup = conn_lookup.cursor()
                    cursor_lookup.execute(f"SELECT estoque_sistema FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo,))
                    resultado_estoque = cursor_lookup.fetchone()
                    if resultado_estoque: # Se o produto foi encontrado
                        # Lógica robusta para lidar com estoque NULL no banco de dados
                        estoque_sistema_no_db = resultado_estoque[0]
                        estoque_sistema_atual = int(estoque_sistema_no_db) if estoque_sistema_no_db is not None else 0
                        backstock_calculado = estoque_sistema_atual - qtd_prateleira
            except Exception as e_lookup:
                logger_app.error(f"Não foi possível buscar o estoque do sistema para o log do produto '{codigo}': {e_lookup}")
            # --------------------------------------------------------------------

            last_log_id = None
            timestamp_atual_log = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_id_log = session.get('user_id')
            username_log = session.get('username')
            try:
                with sqlite3.connect(DATABASE_FILE) as conn_log_initial:
                    cursor_log_initial = conn_log_initial.cursor()
                    cursor_log_initial.execute(f'''
                        INSERT INTO {TABLE_LOG_ENTRADAS_PRATELEIRA} (
                            timestamp, codigo_produto, nome_produto_informado,
                            estoque_sistema_no_momento, qtd_prateleira_informada, qtd_cabe_informada, backstock_calculado,
                            usuario_id, usuario_username
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (timestamp_atual_log, codigo, nome_produto,
                          estoque_sistema_atual, qtd_prateleira, qtd_cabe, backstock_calculado,
                          user_id_log, username_log))
                    last_log_id = cursor_log_initial.lastrowid
                    conn_log_initial.commit()
                    logger_app.info(f"Entrada para '{codigo}' (Log ID: {last_log_id}, Prateleira: {qtd_prateleira}, Cabe: {qtd_cabe}) registrada no log por '{username_log}'.")
            except Exception as e_log_initial:
                logger_app.error(f"Erro ao registrar entrada inicial no log para o código '{codigo}': {e_log_initial}", exc_info=True)
                flash("Erro crítico ao registrar a operação. Ação não processada.", "danger")

            if last_log_id: 
                # Ajustar para esperar apenas dois valores de retorno de processar_entrada_unica
                user_loja = session.get('loja', 'LOJA 1') # Pega a loja do usuário logado
                # --- DEMONSTRATION MODE: Simulate success without Google Sheets ---
                msg_processamento = f"Em modo de demonstração: A entrada para '{nome_produto}' ({codigo}) seria processada. O sistema calcularia o backstock, decidiria entre 'REPOSIÇÃO' ou 'COMPRAS' e atualizaria a planilha correspondente. Se 'Forçar Compra' estivesse ativo, seria enviado para 'COMPRAS'. Se 'Marcar produto na planilha contrária' estivesse ativo, a aba de destino seria invertida."
                flash(msg_processamento, "success")
                logger_app.info(f"DEMO: Entrada para '{codigo}' (Log ID: {last_log_id}) simulada por '{username_log}'.")
                create_notification(user_id_log, f"DEMO: Entrada de {nome_produto} ({codigo}) simulada.", "info")
                # --- END DEMONSTRATION MODE ---

        except ValueError as ve:
            flash(f"Erro de validação: {ve}", "danger")
            logger_app.warning(f"Erro de validação no formulário: {ve}")
        except Exception as e:
            flash(f"Ocorreu um erro ao salvar os dados: {e}", "danger")
            logger_app.error(f"Erro ao processar dados via formulário: {e}", exc_info=True)
        
        return redirect(url_for('index'))

    # Lógica para GET
    ultima_atualizacao_etrade = "Nenhuma atualização registrada." # Default
    try:
        with open("ultima_atualizacao_etrade.txt", "r") as f:
            ultima_atualizacao_etrade = f.read().strip()
    except FileNotFoundError:
        logger_app.info("Arquivo 'ultima_atualizacao_etrade.txt' não encontrado.")
    except Exception as e:
        logger_app.error(f"Erro ao ler 'ultima_atualizacao_etrade.txt': {e}")

    now = datetime.datetime.now().time()
    start_time = datetime.time(7, 0)    # 7:00 AM
    end_time = datetime.time(18, 30) # 6:30 PM
    show_update_message = start_time <= now <= end_time
    logger_app.info(f"Horário atual: {now}. Exibir aviso de atualização: {show_update_message}")

    # Busca a contagem de vendas pendentes para exibir no badge
    pending_sales_count = 0
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Determina o filtro da classe com base na loja do usuário para a contagem de vendas pendentes
        loja_usuario = session.get('loja', 'LOJA 1')
        if loja_usuario == 'LOJA 2':
            filtro_classe = "AND IFNULL(UPPER(etrade.classe), '') = 'PET'"
        else: # LOJA 1 e outros casos
            filtro_classe = "AND IFNULL(UPPER(etrade.classe), '') != 'PET'"

        query = f"""
            SELECT COUNT(log.id)
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG} as log
            INNER JOIN {TABLE_PRODUTOS_ETRADE} as etrade ON log.codigo_produto = etrade.codigo_produto
            WHERE log.status = 'pendente' {filtro_classe}
        """
        cursor.execute(query)
        count_result = cursor.fetchone()
        if count_result:
            pending_sales_count = count_result[0]
        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao buscar contagem de vendas pendentes para o dashboard: {e}", exc_info=True)

    nome_usuario_logado = session.get('nome_completo', session.get('username', 'Usuário'))
    return render_template('index.html', 
                           ultima_atualizacao=ultima_atualizacao_etrade, 
                           show_update_message=show_update_message,
                           nome_usuario=nome_usuario_logado,
                           pending_sales_count=pending_sales_count)

@app.route('/get_last_etrade_update', methods=['GET'])
def get_last_etrade_update_route():
    try:
        with open("ultima_atualizacao_etrade.txt", "r") as f:
            ultima_atualizacao = f.read().strip()
        return jsonify({'last_update': ultima_atualizacao}), 200
    except FileNotFoundError:
        return jsonify({'last_update': 'Nenhuma atualização registrada.'}), 200
    except Exception as e:
        logger_app.error(f"Erro ao ler 'ultima_atualizacao_etrade.txt' para a rota /get_last_etrade_update: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao buscar data de atualização.'}), 500

@app.route('/get_product_name', methods=['GET'])
def get_product_name_route():
    codigo = request.args.get('codigo')
    if not codigo:
        return jsonify({'error': 'Código do produto não fornecido'}), 400

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        # Modificado para buscar também o estoque do sistema
        cursor.execute(f"SELECT nome_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo,))
        resultado = cursor.fetchone()
        conn.close()

        if resultado:
            nome_produto = resultado[0]
            estoque_sistema = resultado[1]
            # Retorna ambos os valores
            return jsonify({'nome_produto': nome_produto, 'estoque_sistema': estoque_sistema})
        else:
            return jsonify({'error': f"Produto com código '{codigo}' não encontrado no banco de dados local E-Trade."}), 404
    except Exception as e:
        logger_app.error(f"Erro ao buscar detalhes do produto (SQLite) para código '{codigo}': {e}", exc_info=True)
        return jsonify({'error': f"Erro interno ao buscar detalhes do produto: {e}"}), 500

@app.route('/service-worker.js')
def serve_service_worker():
    response = send_from_directory(os.path.join(app.root_path, 'static'), 'service-worker.js')
    response.headers['Content-Type'] = 'application/javascript'
    return response

@app.route('/automation_guide')
@login_required
def automation_guide_start():
    """Redireciona para o primeiro passo do guia de automação."""
    return redirect(url_for('automation_guide', step=1))

@app.route('/automation_guide/<int:step>')
@login_required
def automation_guide(step):
    """Exibe um guia passo a passo para preparar o ambiente para a automação."""
    steps = [
        {'title': 'Passo 1: Abra o E-Trade', 'instruction': 'Certifique-se de que o programa E-Trade esteja aberto em sua máquina. Clique em "Próximo" quando estiver pronto.'},
        {'title': 'Passo 2: Navegue até Estoque', 'instruction': 'No menu principal do E-Trade, clique na opção "Estoque".'},
        {'title': 'Passo 3: Navegue até Produtos', 'instruction': 'Dentro do menu "Estoque", clique na opção "Produtos". A lista de todos os produtos deve ser exibida.'},
        {'title': 'Passo 4: Minimize o E-Trade', 'instruction': 'Com a lista de produtos aberta, minimize a janela do E-Trade. Não feche o programa.'},
        {'title': 'Passo 5: Executar Automação', 'instruction': 'Tudo pronto! O sistema agora irá controlar seu mouse e teclado para copiar os dados. Não mexa no computador durante o processo. Clique no botão abaixo para iniciar.'}
    ]
    
    if step < 1 or step > len(steps):
        return redirect(url_for('automation_guide', step=1))

    current_step = steps[step-1]
    is_last_step = (step == len(steps))

    # CORREÇÃO ROBUSTA: Reseta o status da automação sempre que o guia for acessado.
    # Isso garante que, ao entrar em qualquer passo do guia, o status de uma
    # execução anterior (especialmente uma falha) seja limpo da interface.
    status_file = "automation_status.txt"
    try:
        # Escreve 'not_started' para limpar qualquer status anterior ('failed', 'completed', etc.)
        with open(status_file, "w") as f:
            f.write("not_started")
        logger_app.info("Status da automação resetado para 'not_started' ao acessar o guia.")
    except Exception as e:
        logger_app.warning(f"Não foi possível resetar o arquivo de status da automação no guia: {e}")

    return render_template('automation_guide.html', step=step, total_steps=len(steps), current_step=current_step, is_last_step=is_last_step)

@app.route('/run_etrade_automation', methods=['POST'])
@login_required 
def run_etrade_automation_route():
    """Rota para iniciar a automação do E-Trade na máquina local."""
    """
    Modificado para um sistema de Agente.
    Esta rota agora adiciona uma tarefa à fila para o agente do cliente pegar.
    """
    try:
        # Limpa o status de automação anterior para evitar falsos negativos na interface.
        status_file = "automation_status.txt"
        try:
            # Escreve 'queued' para indicar que o comando foi recebido pelo servidor
            # e está aguardando o agente. A interface pode usar isso para mostrar "Aguardando..."
            with open(status_file, "w") as f:
                f.write("queued")
            logger_app.info("Arquivo de status da automação resetado para 'queued'.")
        except Exception as e:
            # Não é um erro fatal, mas é bom registrar.
            logger_app.warning(f"Não foi possível resetar o arquivo de status da automação: {e}")

        # Adiciona a tarefa à fila
        task = {'task': 'run_etrade_automation', 'requested_by': session.get('username')}
        AUTOMATION_TASK_QUEUE.append(task)

        log_audit('automation_triggered', f"Automação E-Trade local disparada por '{session.get('username')}'")
        logger_app.info(f"Tarefa de automação adicionada à fila por '{session.get('username')}'. A fila agora tem {len(AUTOMATION_TASK_QUEUE)} item(ns).")
        
        return jsonify({
            'status': 'success',
            'message': 'Comando de automação enviado para o computador do cliente. A execução começará em breve.'
        }), 200

    except Exception as e:
        logger_app.error(f"Erro ao tentar executar a automação local: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Erro ao iniciar automação: {str(e)}'}), 500

@app.route('/api/agent/get_task', methods=['GET'])
def agent_get_task():
    """
    Endpoint para o agente cliente verificar se há tarefas pendentes.
    """
    # Verificação de segurança: o agente deve enviar a chave secreta correta.
    secret_from_agent = request.headers.get('X-Agent-Secret')
    if not secret_from_agent or secret_from_agent != AGENT_SECRET_KEY:
        logger_app.warning(f"Tentativa de acesso não autorizado ao endpoint do agente do IP: {request.remote_addr}")
        return jsonify({'error': 'Acesso não autorizado'}), 403

    try:
        # Pega a tarefa mais antiga da fila
        task = AUTOMATION_TASK_QUEUE.popleft()
        logger_app.info(f"Entregando tarefa '{task['task']}' para o agente. {len(AUTOMATION_TASK_QUEUE)} tarefa(s) restante(s).")
        return jsonify(task)
    except IndexError:
        # A fila está vazia, o que é normal.
        return jsonify({'task': 'none'})

def process_etrade_data(raw_data):
    """
    Processa os dados brutos do E-Trade recebidos do agente,
    atualiza o banco de dados e registra as vendas.
    """
    logger_app.info("Iniciando processamento dos dados do E-Trade recebidos do agente...")
    
    if not raw_data:
        logger_app.error("Processamento falhou: Nenhum dado foi recebido do agente.")
        return False, "Nenhum dado recebido."

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # 1. Obter o estoque antigo ANTES de qualquer alteração
        logger_app.info("Capturando estoque antigo dos produtos...")
        cursor.execute(f"SELECT codigo_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE}")
        estoque_antigo = {row[0]: row[1] for row in cursor.fetchall()}
        logger_app.info(f"{len(estoque_antigo)} produtos com estoque antigo capturados.")

        # 2. Limpar a tabela de staging para receber os novos dados
        logger_app.info(f"Limpando a tabela de staging '{TABLE_PRODUTOS_ETRADE_STAGING}'...")
        cursor.execute(f"DELETE FROM {TABLE_PRODUTOS_ETRADE_STAGING}")

        linhas = raw_data.strip().split('\n')
        timestamp_atual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        produtos_inseridos = 0
        for i, linha_str in enumerate(linhas):
            colunas = [col.strip() for col in linha_str.split('\t')]
            
            if len(colunas) >= 9: 
                try:
                    codigo_prod, nome_prod, un_vnd_val, preco_str, estoque_str, codigo_ean_val, marca_val, classe_val, subclasse_val = colunas[:9]

                    preco_val = float(preco_str.replace(',', '.')) if preco_str else 0.0
                    estoque_val = int(float(estoque_str.replace(',', '.'))) if estoque_str else 0
                    
                    if codigo_prod:
                        cursor.execute(f'''
                            INSERT INTO {TABLE_PRODUTOS_ETRADE_STAGING} 
                            (codigo_produto, nome_produto, un_vnd, preco, estoque_sistema, 
                             codigo_ean, marca, classe, subclasse, ultima_atualizacao_etrade) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (codigo_prod, nome_prod, un_vnd_val, preco_val, estoque_val,
                              codigo_ean_val, marca_val, classe_val, subclasse_val, timestamp_atual))
                        produtos_inseridos += 1
                except (ValueError, IndexError) as e_row:
                    logger_app.warning(f"AVISO: Erro ao processar linha {i+1} ('{linha_str[:50]}...'): {e_row}. Linha ignorada.")
            else:
                logger_app.warning(f"AVISO: Linha {i+1} não tem colunas suficientes (esperado >=9, encontrado {len(colunas)}). Linha ignorada: '{linha_str[:50]}...'")

        conn.commit()
        logger_app.info(f"{produtos_inseridos} produtos salvos na tabela de staging '{TABLE_PRODUTOS_ETRADE_STAGING}'.")

        # 3. Atualizar a tabela principal a partir da staging dentro de uma transação
        logger_app.info("Iniciando transação para atualizar a tabela principal de produtos...")
        # A transação é iniciada implicitamente pela primeira instrução de modificação de dados (DELETE).
        # A forma correta de confirmar (commit) a transação é usando o objeto de conexão.
        cursor.execute(f"DELETE FROM {TABLE_PRODUTOS_ETRADE}")
        cursor.execute(f"INSERT INTO {TABLE_PRODUTOS_ETRADE} SELECT * FROM {TABLE_PRODUTOS_ETRADE_STAGING}")
        conn.commit() # CORREÇÃO: Usa conn.commit() em vez de cursor.execute("COMMIT")
        logger_app.info(f"Tabela principal '{TABLE_PRODUTOS_ETRADE}' atualizada com sucesso.")

        # 4. Limpar logs pendentes e registrar novos produtos vendidos
        logger_app.info("Comparando estoques e registrando produtos vendidos...")
        cursor.execute(f"DELETE FROM {TABLE_PRODUTOS_VENDIDOS_LOG} WHERE status = 'pendente'")
        conn.commit()
        logger_app.info("Logs de vendas pendentes anteriores foram limpos.")

        cursor.execute(f"SELECT codigo_produto, nome_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE_STAGING}")
        produtos_novos = cursor.fetchall()
        
        produtos_vendidos_registrados = 0
        for codigo_novo, nome_novo, estoque_novo_val in produtos_novos:
            estoque_antigo_val = estoque_antigo.get(codigo_novo)
            if estoque_antigo_val is not None and estoque_novo_val is not None and estoque_novo_val < estoque_antigo_val:
                quantidade_vendida = estoque_antigo_val - estoque_novo_val
                data_verificacao = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(f'''
                    INSERT INTO {TABLE_PRODUTOS_VENDIDOS_LOG}
                    (codigo_produto, nome_produto, estoque_anterior, estoque_novo, quantidade_vendida, data_verificacao, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (codigo_novo, nome_novo, estoque_antigo_val, estoque_novo_val, quantidade_vendida, data_verificacao, 'pendente'))
                produtos_vendidos_registrados += 1
        
        conn.commit()
        logger_app.info(f"{produtos_vendidos_registrados} produtos vendidos foram registrados para revisão.")
        conn.close()

        # 5. Salvar timestamp da última atualização
        with open("ultima_atualizacao_etrade.txt", "w") as f:
            f.write(timestamp_atual)
        logger_app.info(f"Timestamp da última atualização ({timestamp_atual}) salvo em 'ultima_atualizacao_etrade.txt'.")

        return True, f"{produtos_inseridos} produtos atualizados e {produtos_vendidos_registrados} vendas registradas."

    except Exception as e:
        logger_app.error(f"ERRO CRÍTICO ao processar dados do E-Trade: {e}", exc_info=True)
        if 'conn' in locals() and conn:
            conn.close()
        return False, f"Erro no servidor: {e}"

@app.route('/admin/dismissed_sales_log')
@login_required
def dismissed_sales_log():
    """Página para visualizar e restaurar avisos de venda descartados."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Busca logs com status 'descartado'
        cursor.execute(f"""
            SELECT id, codigo_produto, nome_produto, quantidade_vendida, data_verificacao
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG}
            WHERE status = 'descartado'
            ORDER BY data_verificacao DESC
        """)
        dismissed_logs = cursor.fetchall()
        conn.close()
        
        return render_template('dismissed_sales_log.html', logs=dismissed_logs)
    except Exception as e:
        logger_app.error(f"Erro ao carregar logs de venda descartados: {e}", exc_info=True)
        flash('Erro ao carregar a lista de avisos descartados.', 'danger')
        return redirect(url_for('review_sales'))

@app.route('/admin/restore_sale_log/<int:log_id>', methods=['POST'])
@login_required
def restore_sale_log(log_id):
    """Restaura um log de venda do status 'descartado' para 'pendente'."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Atualiza o status para 'pendente'
        cursor.execute(f"UPDATE {TABLE_PRODUTOS_VENDIDOS_LOG} SET status = 'pendente' WHERE id = ?", (log_id,))
        
        if cursor.rowcount > 0:
            conn.commit()
            flash('Aviso de venda restaurado com sucesso! Ele aparecerá na tela de revisão.', 'success')
            log_audit('sales_log_restore', f"Log de venda ID {log_id} restaurado por '{session.get('username')}'")
        else:
            flash('Aviso não encontrado ou já restaurado.', 'warning')
            
        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao restaurar log de venda ID {log_id}: {e}", exc_info=True)
        flash('Erro ao restaurar o aviso de venda.', 'danger')

    return redirect(url_for('dismissed_sales_log'))


@app.route('/review_sales', methods=['GET', 'POST'])
@login_required
def review_sales():
    if request.method == 'POST':
        action = request.form.get('action') # Identifica qual botão foi pressionado
        selected_product_codes = request.form.getlist('repor_produto')

        if not selected_product_codes:
            flash('Nenhum produto foi selecionado.', 'warning')
            return redirect(url_for('review_sales'))

        # Lógica para o novo botão "Descartar Selecionados"
        if action == 'dismiss':
            try:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                for codigo in selected_product_codes:
                    # Altera o status para 'descartado' para que não apareça mais na lista de pendentes
                    cursor.execute(f"UPDATE {TABLE_PRODUTOS_VENDIDOS_LOG} SET status = 'descartado' WHERE codigo_produto = ? AND status = 'pendente'", (codigo,))
                conn.commit()
                
                count = len(selected_product_codes)
                flash(f'{count} aviso(s) de venda foram descartados com sucesso.', 'success')
                log_audit('sales_log_dismiss', f"{count} logs de venda descartados por '{session.get('username')}' para os códigos: {', '.join(selected_product_codes)}")
            
            except Exception as e:
                flash(f'Erro ao descartar avisos: {e}', 'danger')
                logger_app.error(f"Erro ao descartar logs de venda: {e}", exc_info=True)
            finally:
                if 'conn' in locals() and conn:
                    conn.close()
            return redirect(url_for('review_sales'))

        try:
            # Lógica original para processar os produtos (agora acionada pelo botão "Processar")
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # --- DEMONSTRATION MODE: Simulate success without Google Sheets ---
            logger_app.info("DEMO: Simulação de processamento de vendas selecionadas.")
            processed_count = 0
            errors = []

            for codigo in selected_product_codes:
                try:
                    # Recupera os valores de qtd_prateleira e qtd_cabe para este produto específico
                    qtd_prateleira_str = request.form.get(f'qtd_prateleira_{codigo}')

                    if not qtd_prateleira_str:
                        errors.append(f"Quantidade na prateleira não informada para o produto {codigo}. Ignorando.")
                        continue

                    qtd_prateleira = int(qtd_prateleira_str)

                    # Lógica para calcular a "quantidade que cabe" dinamicamente.
                    # O objetivo é repor exatamente a quantidade que foi vendida.
                    cursor.execute(f"SELECT quantidade_vendida FROM {TABLE_PRODUTOS_VENDIDOS_LOG} WHERE codigo_produto = ? AND status = 'pendente'", (codigo,))
                    log_info = cursor.fetchone()
                    if not log_info:
                        errors.append(f"Não foi possível encontrar o log de venda pendente para o produto {codigo} para calcular a reposição. Ignorando.")
                        continue
                    quantidade_vendida = log_info[0]
                    qtd_cabe = qtd_prateleira + quantidade_vendida

                    # Busca o nome do produto no DB para passar para processar_entrada_unica
                    cursor.execute(f"SELECT nome_produto FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo,))
                    product_info = cursor.fetchone()
                    if not product_info:
                        errors.append(f"Produto {codigo} não encontrado no banco de dados E-Trade para processamento. Ignorando.")
                        continue
                    nome_produto = product_info[0]

                    # Verifica se a opção de forçar compra foi marcada para este produto
                    forcar_compra_especifica = f'forcar_compra_{codigo}' in request.form

                    # Chama a lógica existente em main_logic.py
                    # In demonstration mode, we just simulate the action.
                    # We still update the local DB status to 'processed' for the demo to reflect changes.
                    cursor.execute(f"UPDATE {TABLE_PRODUTOS_VENDIDOS_LOG} SET status = 'processado' WHERE codigo_produto = ? AND status = 'pendente'", (codigo,))
                    conn.commit()
                    processed_count += 1
                    flash(f"DEMO: Produto {codigo} ({nome_produto}) seria processado. Uma entrada seria criada na planilha de 'REPOSIÇÃO' ou 'COMPRAS' conforme o backstock e a opção 'Forçar Compra'.", 'info')

                # --- END DEMONSTRATION MODE ---

                except ValueError as ve:
                    errors.append(f"Erro de valor para {codigo}: {ve}. Ignorando.")
                except Exception as e:
                    errors.append(f"Erro inesperado ao processar {codigo}: {e}. Ignorando.")
                    logger_app.error(f"Erro ao processar produto {codigo} em review_sales: {e}", exc_info=True)
            
            conn.close()

            if processed_count > 0:
                flash(f'{processed_count} produto(s) processado(s) com sucesso.', 'success')
            if errors:
                for error_msg in errors:
                    flash(error_msg, 'danger')
            
            # Sempre redireciona para o GET para atualizar a lista de itens pendentes
            return redirect(url_for('review_sales'))

        except Exception as e_outer:
            logger_app.error(f"Erro geral na rota review_sales (POST): {e_outer}", exc_info=True)
            flash(f'Ocorreu um erro geral ao processar a revisão de vendas: {e_outer}', 'danger')
        return redirect(url_for('index'))

    # Lógica para GET
    try:
        codigos_em_aberto = set() # Default para vazio se a comunicação com GS falhar
        # --- DEMONSTRATION MODE: No Google Sheets check ---
        logger_app.info("DEMO: Pulando verificação de produtos em aberto no Google Sheets.")
        # --- END DEMONSTRATION MODE ---
 
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # --- LÓGICA MULTILOJA PARA QUERY SQL ---
        loja_usuario = session.get('loja', 'LOJA 1')
        acesso_multiloja = session.get('acesso_multiloja', 0)
        filtro_classe = "" # Inicia sem filtro

        if not acesso_multiloja:
            # Aplica filtro apenas se o usuário NÃO for multiloja
            if loja_usuario == 'LOJA 2':
                filtro_classe = "AND IFNULL(UPPER(etrade.classe), '') = 'PET'"
                logger_app.info(f"Usuário da LOJA 2. Filtrando para incluir APENAS a classe 'PET'.")
            else: # LOJA 1 e outros casos
                filtro_classe = "AND IFNULL(UPPER(etrade.classe), '') != 'PET'"
                logger_app.info(f"Usuário da LOJA 1. Filtrando para EXCLUIR a classe 'PET'.")
        else:
            logger_app.info("Usuário com acesso multiloja. Exibindo produtos de todas as classes.")

        # A query agora junta a tabela de log de vendas com a de produtos para filtrar pela classe
        query = f"""
            SELECT
                log.codigo_produto, log.nome_produto, log.estoque_anterior,
                log.estoque_novo, log.quantidade_vendida
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG} as log
            INNER JOIN {TABLE_PRODUTOS_ETRADE} as etrade ON log.codigo_produto = etrade.codigo_produto
            WHERE log.status = 'pendente' {filtro_classe}
        """
        cursor.execute(query)
        produtos_vendidos = cursor.fetchall()
        conn.close()

        # Filtra os produtos que já estão marcados como 'ABERTO' na planilha do Google Sheets (em modo demo, este filtro não fará nada)
        produtos_para_revisao = [
            p for p in produtos_vendidos if str(p[0]) not in codigos_em_aberto
        ]
        
        logger_app.info(f"{len(produtos_para_revisao)} produtos vendidos encontrados para revisão.")
        return render_template('review_sales.html', produtos=produtos_para_revisao)
    except Exception as e:
        logger_app.error(f"Erro ao carregar a página de revisão de vendas: {e}", exc_info=True)
        flash(f'Erro ao carregar dados para revisão: {e}', 'danger')
        return redirect(url_for('index'))

@app.route('/automation_status', methods=['GET'])
@login_required
def automation_status():
    try:
        with open("automation_status.txt", "r") as f:
            status = f.read().strip()
        return jsonify({'status': status})
    except FileNotFoundError:
        return jsonify({'status': 'not_started'})
    except Exception as e:
        logger_app.error(f"Erro ao ler arquivo de status da automação: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/system_settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    if request.method == 'POST':
        sales_analysis_period_days = request.form.get('sales_analysis_period_days', type=int)
        
        if sales_analysis_period_days is None or sales_analysis_period_days <= 0:
            flash('Período de análise de vendas deve ser um número positivo.', 'danger')
        else:
            try:
                cursor.execute(f"REPLACE INTO {TABLE_SETTINGS} (setting_name, setting_value) VALUES (?, ?)",
                               ('SALES_ANALYSIS_PERIOD_DAYS', str(sales_analysis_period_days)))
                conn.commit()
                flash('Configurações atualizadas com sucesso!', 'success')
                log_audit('system_setting_update', f"Período de análise de vendas alterado para {sales_analysis_period_days} por '{session.get('username')}'")
            except Exception as e:
                flash(f'Erro ao atualizar configurações: {e}', 'danger')
                logger_app.error(f"Erro ao atualizar configurações do sistema: {e}", exc_info=True)

    # Carrega as configurações atuais
    current_settings = {}
    try:
        cursor.execute(f"SELECT setting_name, setting_value FROM {TABLE_SETTINGS}")
        for row in cursor.fetchall():
            current_settings[row[0]] = row[1]
    except Exception as e:
        logger_app.error(f"Erro ao carregar configurações do sistema: {e}", exc_info=True)
        flash('Erro ao carregar configurações.', 'danger')

    conn.close()
    # Converte para int para o template, usando um fallback se não estiver presente
    current_settings['SALES_ANALYSIS_PERIOD_DAYS'] = int(current_settings.get('SALES_ANALYSIS_PERIOD_DAYS', SALES_ANALYSIS_PERIOD_DAYS))

    return render_template('system_settings.html', settings=current_settings)

@app.route('/operator_dashboard')
@login_required
def operator_dashboard():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id:
        flash('Sua sessão não está ativa. Por favor, faça login novamente.', 'danger')
        return redirect(url_for('login'))

    dashboard_data = {
        'total_entries_today': 0,
        'total_entries_last_7_days': 0,
        'top_products_entered': [],
        'last_5_entries': [],
        'entries_by_day': {'labels': [], 'data': []} # Inicializa para o gráfico
    }

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total entries today by user
        today = datetime.date.today().strftime("%Y-%m-%d")
        cursor.execute(f"SELECT COUNT(id) FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} WHERE usuario_id = ? AND date(timestamp) = ?", (user_id, today))
        dashboard_data['total_entries_today'] = cursor.fetchone()[0]

        # Total entries last 7 days by user
        seven_days_ago = (datetime.date.today() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
        cursor.execute(f"SELECT COUNT(id) FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} WHERE usuario_id = ? AND date(timestamp) >= ?", (user_id, seven_days_ago))
        dashboard_data['total_entries_last_7_days'] = cursor.fetchone()[0]

        # Top 3 products entered by user
        cursor.execute(f"""
            SELECT codigo_produto, nome_produto_informado, COUNT(id) as total_entries
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            WHERE usuario_id = ?
            GROUP BY codigo_produto, nome_produto_informado
            ORDER BY total_entries DESC
            LIMIT 3
        """, (user_id,))
        dashboard_data['top_products_entered'] = cursor.fetchall()

        # Last 5 entries by user
        cursor.execute(f"""
            SELECT timestamp, codigo_produto, nome_produto_informado, qtd_prateleira_informada, backstock_calculado
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            WHERE usuario_id = ?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (user_id,))
        dashboard_data['last_5_entries'] = cursor.fetchall()

        # Dados para o gráfico de atividade (entradas por dia nos últimos 7 dias)
        cursor.execute(f"""
            SELECT date(timestamp) as dia, COUNT(id) as total
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            WHERE usuario_id = ? AND date(timestamp) >= date('now', '-7 days')
            GROUP BY dia
            ORDER BY dia ASC
        """, (user_id,))
        entries_by_day_raw = cursor.fetchall()

        # Prepara os dados para o Chart.js, garantindo que todos os 7 dias estejam presentes
        labels = [(datetime.date.today() - datetime.timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
        data_map = {row['dia']: row['total'] for row in entries_by_day_raw}
        data_points = [data_map.get(label, 0) for label in labels]

        dashboard_data['entries_by_day'] = {'labels': labels, 'data': data_points}

        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao carregar dashboard do operador para '{username}': {e}", exc_info=True)
        flash('Erro ao carregar seu dashboard.', 'danger')
        return redirect(url_for('index'))

    return render_template('operator_dashboard.html', dashboard_data=dashboard_data, username=username)

@app.route('/my_entries')
@login_required
def my_entries():
    user_id = session.get('user_id')
    if not user_id:
        flash('Sua sessão não está ativa. Por favor, faça login novamente.', 'danger')
        return redirect(url_for('login'))

    # Parâmetros de filtro e paginação
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = 20 # Quantidade de registros por página
    offset = (page - 1) * per_page

    query = f"""
        SELECT timestamp, codigo_produto, nome_produto_informado, estoque_sistema_no_momento,
               qtd_prateleira_informada, qtd_cabe_informada, backstock_calculado
        FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
        WHERE usuario_id = ?
    """
    params = [user_id]

    if start_date:
        query += " AND date(timestamp) >= ?"
        params.append(start_date)
    if end_date:
        query += " AND date(timestamp) <= ?"
        params.append(end_date)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        logs = cursor.fetchall()
        conn.close()
        return render_template('my_entries.html', logs=logs, page=page, per_page=per_page, start_date=start_date, end_date=end_date)
    except Exception as e:
        logger_app.error(f"Erro ao buscar logs de entrada do usuário {user_id}: {e}", exc_info=True)
def export_my_entries_csv():
    user_id = session.get('user_id')
    if not user_id:
        flash('Sua sessão não está ativa. Por favor, faça login novamente.', 'danger')

        return redirect(url_for('login'))

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = f"""
        SELECT timestamp, codigo_produto, nome_produto_informado, estoque_sistema_no_momento,
               qtd_prateleira_informada, qtd_cabe_informada, backstock_calculado, usuario_username
        FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
        WHERE usuario_id = ?
    """
    params = [user_id]

    if start_date:
        query += " AND date(timestamp) >= ?"
        params.append(start_date)
    if end_date:
        query += " AND date(timestamp) <= ?"
        params.append(end_date)

    query += " ORDER BY timestamp DESC"

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(query, tuple(params))
    logs = cursor.fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Data/Hora', 'Codigo Produto', 'Nome Produto', 'Estoque Sistema no Momento', 'Qtd Prateleira', 'Qtd Cabe', 'Backstock Calculado', 'Usuario'])
    cw.writerows(logs)

    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=meus_registros_entradas_{start_date or 'inicio'}_a_{end_date or 'fim'}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/products')
@login_required
def products():
    search_query = request.args.get('q', '')
    products_list = []
    if search_query:
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Search in product name and code
            term = f"%{search_query}%"
            cursor.execute(f"""
                SELECT codigo_produto, nome_produto, estoque_sistema, marca, classe, preco 
                FROM {TABLE_PRODUTOS_ETRADE} 
                WHERE nome_produto LIKE ? OR codigo_produto LIKE ?
                ORDER BY nome_produto
            """, (term, term))
            products_list = cursor.fetchall()
            conn.close()
        except Exception as e:
            logger_app.error(f"Erro ao buscar produtos: {e}", exc_info=True)
            flash('Erro ao realizar a busca de produtos.', 'danger')
    
    return render_template('products.html', products=products_list, search_query=search_query)

@app.route('/search')
@login_required
def global_search():
    search_query = request.args.get('q', '').strip()
    results = {
        'products': [],
        'users': [],
        'reports': []
    }

    if not search_query:
        # Apenas renderiza a página vazia com a instrução para buscar
        return render_template('search_results.html', query=search_query, results=results)

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.create_function("unaccent", 1, remove_accents) # Permite busca sem acentos
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        term = f"%{search_query}%"
        unaccented_term = f"%{remove_accents(search_query.lower())}%"
        
        # 1. Busca por produtos
        cursor.execute(f"""
            SELECT codigo_produto, nome_produto, estoque_sistema
            FROM {TABLE_PRODUTOS_ETRADE} 
            WHERE unaccent(LOWER(nome_produto)) LIKE ? OR codigo_produto LIKE ? OR codigo_ean LIKE ?
            ORDER BY nome_produto
            LIMIT 10
        """, (unaccented_term, term, term))
        results['products'] = cursor.fetchall()

        # 2. Busca por usuários (apenas se for Admin)
        if session.get('cargo') == 'Admin':
            cursor.execute(f"""
                SELECT id, username, nome_completo, cargo
                FROM {TABLE_USUARIOS}
                WHERE unaccent(LOWER(username)) LIKE ? OR unaccent(LOWER(nome_completo)) LIKE ?
                ORDER BY username
                LIMIT 10
            """, (unaccented_term, unaccented_term))
            results['users'] = cursor.fetchall()
        
        conn.close()

        # 3. Busca por páginas e relatórios (lista estática, filtrada no Python)
        # Organizado por categoria para melhor agrupamento nos resultados de busca
        all_pages = [
            # -- PÁGINAS GERAIS --
            {'name': 'Dashboard', 'url': url_for('dashboard'), 'admin_only': True},
            {'name': 'Gerenciar Usuários', 'url': url_for('admin_users'), 'admin_only': True},
            {'name': 'Relatório de Estoque Crítico', 'url': url_for('report_critical_stock'), 'admin_only': True},
            {'name': 'Relatório de Estoque Parado', 'url': url_for('report_stagnant_stock'), 'admin_only': True},
            {'name': 'Relatório de Ruptura de Estoque', 'url': url_for('report_stock_rupture'), 'admin_only': True},
            {'name': 'Relatório de Velocidade de Vendas', 'url': url_for('report_sales_velocity'), 'admin_only': True},
            {'name': 'Relatório de Histórico de Vendas', 'url': url_for('report_sales_history'), 'admin_only': True},
            {'name': 'Relatório de Valor de Inventário', 'url': url_for('report_inventory_value'), 'admin_only': True},
            {'name': 'Análise de Vendas', 'url': url_for('sales_analysis'), 'admin_only': True},
            {'name': 'Meus Registros', 'url': url_for('my_entries'), 'admin_only': False},
            {'name': 'Reportar Problema/Sugestão', 'url': url_for('report_issue'), 'admin_only': False},
            {'name': 'Visualizador de Log', 'url': url_for('log_viewer'), 'admin_only': True},
        ]

        # Filtra as páginas com base na busca e no cargo do usuário
        for page in all_pages:
            if search_query.lower() in page['name'].lower():
                if not page['admin_only'] or (page['admin_only'] and session.get('cargo') == 'Admin'):
                    results['reports'].append(page)

    except Exception as e:
        logger_app.error(f"Erro na busca global por '{search_query}': {e}", exc_info=True)
        flash('Ocorreu um erro ao realizar a busca.', 'danger')

    return render_template('search_results.html', query=search_query, results=results)


@app.route('/switch_store')
@login_required
def switch_store():
    if session.get('cargo') != 'Admin':
        flash('Apenas administradores podem alternar entre lojas.', 'danger')
        return redirect(request.referrer or url_for('index'))

    current_store = session.get('loja', 'LOJA 1')
    
    new_store = 'LOJA 2' if current_store == 'LOJA 1' else 'LOJA 1'
        
    session['loja'] = new_store
    flash(f'Visão alterada para {new_store}.', 'success')
    
    # Redireciona de volta para a página em que o usuário estava
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/logs_entradas')
@login_required
def admin_logs_entradas():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado a esta página.', 'danger')
        logger_app.warning(f"Tentativa de acesso não autorizado à página de logs por '{session.get('username', 'desconhecido')}'.")
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT timestamp, codigo_produto, nome_produto_informado, estoque_sistema_no_momento,
                   qtd_prateleira_informada, qtd_cabe_informada, backstock_calculado, usuario_username
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} 
            ORDER BY timestamp DESC
        """)
        logs = cursor.fetchall()
        conn.close()
        return render_template('logs_entradas.html', logs=logs)
    except Exception as e:
        logger_app.error(f"Erro ao buscar logs de entrada: {e}", exc_info=True)
        flash('Erro ao carregar os logs de entrada.', 'danger')
        return render_template('logs_entradas.html', logs=[])

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado a esta página.', 'danger')
        return redirect(url_for('index'))

    ultima_atualizacao_etrade = "Nenhuma atualização registrada." # Default
    try:
        with open("ultima_atualizacao_etrade.txt", "r") as f:
            ultima_atualizacao_etrade = f.read().strip()
    except FileNotFoundError:
        logger_app.info("Arquivo 'ultima_atualizacao_etrade.txt' não encontrado.")
    except Exception as e:
        logger_app.error(f"Erro ao ler 'ultima_atualizacao_etrade.txt': {e}")

    dashboard_data = {
        'entradas_hoje': 0,
        'top_usuarios': [],
        'top_produtos': [],
        'alertas_estoque': []
    }

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # 1. Total de entradas hoje
        hoje = datetime.date.today().strftime("%Y-%m-%d")
        cursor.execute(f"SELECT COUNT(id) FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} WHERE date(timestamp) = ?", (hoje,))
        dashboard_data['entradas_hoje'] = cursor.fetchone()[0]

        # 2. Top 5 usuários por atividade
        cursor.execute(f"""
            SELECT usuario_username, COUNT(id) as total FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            WHERE usuario_username IS NOT NULL GROUP BY usuario_username ORDER BY total DESC LIMIT 5
        """)
        dashboard_data['top_usuarios'] = cursor.fetchall()

        # 3. Top 5 produtos mais registrados
        cursor.execute(f"""
            SELECT codigo_produto, nome_produto_informado, COUNT(id) as total FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            GROUP BY codigo_produto, nome_produto_informado
            ORDER BY total DESC
            LIMIT 5
        """)
        dashboard_data['top_produtos'] = cursor.fetchall()

        # 4. Últimos 5 alertas de estoque (backstock negativo)
        cursor.execute(f"""
            SELECT timestamp, codigo_produto, nome_produto_informado, estoque_sistema_no_momento, qtd_prateleira_informada, backstock_calculado, usuario_username
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} WHERE backstock_calculado < 0 ORDER BY timestamp DESC LIMIT 5
        """)
        dashboard_data['alertas_estoque'] = cursor.fetchall()
        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao carregar dados para o dashboard: {e}", exc_info=True)
        flash('Erro ao carregar os dados do dashboard.', 'danger')

    return render_template('dashboard.html', data=dashboard_data, ultima_atualizacao_etrade=ultima_atualizacao_etrade)

@app.route('/admin/users')
@login_required
def admin_users():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, nome_completo, cargo, loja, nome_planilha FROM {TABLE_USUARIOS} ORDER BY username")
        users = cursor.fetchall()
        conn.close()
        return render_template('admin_users.html', users=users)
    except Exception as e:
        logger_app.error(f"Erro ao buscar lista de usuários: {e}", exc_info=True)
        flash('Erro ao carregar a lista de usuários.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(f"SELECT * FROM {TABLE_USUARIOS} WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('Usuário não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        nome_completo = request.form.get('nome_completo')
        cargo = request.form.get('cargo')
        loja = request.form.get('loja')
        nome_planilha = request.form.get('nome_planilha')
        password = request.form.get('password')
        acesso_multiloja = 1 if 'acesso_multiloja' in request.form else 0

        if not all([nome_completo, cargo, loja, nome_planilha]):
            flash('Nome completo, cargo, loja e nome na planilha são obrigatórios.', 'error')
        elif loja not in ['LOJA 1', 'LOJA 2']:
            flash('Loja inválida selecionada.', 'error')
        else:
            try:
                if password:
                    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                    cursor.execute(f"UPDATE {TABLE_USUARIOS} SET nome_completo = ?, cargo = ?, loja = ?, nome_planilha = ?, acesso_multiloja = ?, password_hash = ? WHERE id = ?", (nome_completo, cargo, loja, nome_planilha, acesso_multiloja, hashed_password, user_id))
                    logger_app.info(f"Usuário ID {user_id} ({user['username']}) atualizado com nova senha por '{session.get('username')}'.")
                else:
                    cursor.execute(f"UPDATE {TABLE_USUARIOS} SET nome_completo = ?, cargo = ?, loja = ?, nome_planilha = ?, acesso_multiloja = ? WHERE id = ?", (nome_completo, cargo, loja, nome_planilha, acesso_multiloja, user_id))
                    logger_app.info(f"Usuário ID {user_id} ({user['username']}) atualizado por '{session.get('username')}'.")
                conn.commit()
                log_audit('user_update', f"Usuário ID {user_id} ({user['username']}) atualizado por '{session.get('username')}'")
                flash('Usuário atualizado com sucesso!', 'success')
                conn.close()
                return redirect(url_for('admin_users'))
            except Exception as e:
                flash(f'Erro ao atualizar usuário: {e}', 'danger')
                logger_app.error(f"Erro ao atualizar usuário ID {user_id}: {e}", exc_info=True)
        
        conn.close()
        return redirect(url_for('edit_user', user_id=user_id))

    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    if user_id == session.get('user_id'):
        flash('Você não pode deletar a si mesmo.', 'danger')
        return redirect(url_for('admin_users'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {TABLE_USUARIOS} WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        log_audit('user_delete', f"Usuário ID {user_id} deletado por '{session.get('username')}'")
        flash('Usuário deletado com sucesso.', 'success')
        logger_app.info(f"Usuário ID {user_id} deletado por '{session.get('username')}'.")
    except Exception as e:
        flash(f'Erro ao deletar usuário: {e}', 'danger')
        logger_app.error(f"Erro ao deletar usuário ID {user_id}: {e}", exc_info=True)

    return redirect(url_for('admin_users'))

@app.route('/admin/receive_stock', methods=['GET', 'POST'])
@login_required
def receive_stock():
    """Página para registrar a entrada de mercadorias com lote e validade."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        codigo_produto = request.form.get('codigo_produto')
        numero_lote = request.form.get('numero_lote')
        quantidade_str = request.form.get('quantidade')
        data_validade = request.form.get('data_validade')

        if not all([codigo_produto, quantidade_str]):
            flash('Código do produto e quantidade são obrigatórios.', 'danger')
            return redirect(url_for('receive_stock'))

        try:
            quantidade = int(quantidade_str)
            if quantidade <= 0:
                raise ValueError("A quantidade deve ser um número positivo.")

            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Verifica se o produto existe na tabela principal
            cursor.execute(f"SELECT nome_produto FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto,))
            if not cursor.fetchone():
                flash(f"Produto com código '{codigo_produto}' não encontrado no banco de dados E-Trade.", 'danger')
                conn.close()
                return redirect(url_for('receive_stock'))

            # 1. Insere o novo lote na tabela de lotes
            cursor.execute(f"""
                INSERT INTO {TABLE_LOTES_PRODUTOS} (codigo_produto, numero_lote, quantidade, data_entrada, data_validade, usuario_id, usuario_username)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (codigo_produto, numero_lote, quantidade, datetime.date.today().isoformat(), data_validade or None, session.get('user_id'), session.get('username')))

            # 2. Atualiza o estoque geral na tabela produtos_etrade
            cursor.execute(f"""
                UPDATE {TABLE_PRODUTOS_ETRADE}
                SET estoque_sistema = estoque_sistema + ?
                WHERE codigo_produto = ?
            """, (quantidade, codigo_produto))

            conn.commit()
            conn.close()
            flash(f"Entrada de {quantidade} unidade(s) do produto {codigo_produto} (Lote: {numero_lote or 'N/A'}) registrada com sucesso!", 'success')
            logger_app.info(f"Entrada de estoque registrada por '{session.get('username')}': {quantidade}x {codigo_produto}, Lote: {numero_lote}")

        except ValueError as ve:
            flash(f"Erro de validação: {ve}", 'danger')
        except Exception as e:
            flash(f"Erro ao registrar entrada de estoque: {e}", 'danger')
            logger_app.error(f"Erro em receive_stock (POST): {e}", exc_info=True)

        return redirect(url_for('receive_stock'))

    # Para requisição GET, apenas renderiza a página
    return render_template('receive_stock.html')

@app.route('/admin/expiry_report')
@login_required
def expiry_report():
    """Relatório de produtos com data de validade próxima."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    days_threshold = request.args.get('days', 30, type=int)
    target_date = (datetime.date.today() + datetime.timedelta(days=days_threshold)).isoformat()

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row # Permite acessar colunas pelo nome
        cursor = conn.cursor()

        # Busca lotes que expiram dentro do período ou já expiraram, e que ainda têm quantidade
        cursor.execute(f"""
            SELECT
                l.id,
                l.codigo_produto,
                p.nome_produto,
                l.numero_lote,
                l.quantidade,
                l.data_validade,
                CAST(julianday(l.data_validade) - julianday('now') AS INTEGER) as dias_restantes
            FROM {TABLE_LOTES_PRODUTOS} l
            JOIN {TABLE_PRODUTOS_ETRADE} p ON l.codigo_produto = p.codigo_produto
            WHERE l.data_validade IS NOT NULL
              AND l.data_validade != ''
              AND l.data_validade <= ?
              AND l.quantidade > 0
            ORDER BY l.data_validade ASC
        """, (target_date,))
        expiring_lots = cursor.fetchall()
        conn.close()

        return render_template('expiry_report.html', lots=expiring_lots, threshold=days_threshold)

    except Exception as e:
        flash(f"Erro ao gerar relatório de validade: {e}", 'danger')
        logger_app.error(f"Erro em expiry_report: {e}", exc_info=True)
        return redirect(url_for('dashboard'))

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def edit_lot(lot_id):
    """Página para editar um lote existente (quantidade, data de validade)."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        nova_quantidade_str = request.form.get('quantidade')
        nova_data_validade = request.form.get('data_validade')
        novo_numero_lote = request.form.get('numero_lote')

        try:
            nova_quantidade = int(nova_quantidade_str)
            if nova_quantidade < 0:
                raise ValueError("A quantidade não pode ser negativa.")

            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE {TABLE_LOTES_PRODUTOS}
                SET quantidade = ?, data_validade = ?, numero_lote = ?
                WHERE id = ?
            """, (nova_quantidade, nova_data_validade or None, novo_numero_lote, lot_id))
            conn.commit()
            conn.close()

            flash('Lote atualizado com sucesso!', 'success')
            logger_app.info(f"Lote ID {lot_id} atualizado por '{session.get('username')}'. Nova Qtd: {nova_quantidade}, Nova Validade: {nova_data_validade}")
            return redirect(url_for('expiry_report'))

        except ValueError as ve:
            flash(f"Erro de validação: {ve}", 'danger')
        except Exception as e:
            flash(f"Erro ao atualizar o lote: {e}", 'danger')
            logger_app.error(f"Erro em edit_lot (POST) para lot_id {lot_id}: {e}", exc_info=True)
        
        # Em caso de erro, redireciona de volta para a página de edição
        return redirect(url_for('edit_lot', lot_id=lot_id))

    # Lógica para GET
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT l.*, p.nome_produto
            FROM {TABLE_LOTES_PRODUTOS} l
            JOIN {TABLE_PRODUTOS_ETRADE} p ON l.codigo_produto = p.codigo_produto
            WHERE l.id = ?
        """, (lot_id,))
        lot_data = cursor.fetchone()
        conn.close()

        return render_template('edit_lot.html', lot=lot_data)
    except Exception as e:
        flash(f"Erro ao carregar dados do lote para edição: {e}", 'danger')
        return redirect(url_for('expiry_report'))

@app.route('/admin/stock_adjustment', methods=['GET', 'POST'])
@login_required
def stock_adjustment():
    """Página para ajuste manual de estoque."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        codigo_produto = request.form.get('codigo_produto')
        novo_estoque_str = request.form.get('novo_estoque')
        motivo = request.form.get('motivo')

        if not all([codigo_produto, novo_estoque_str, motivo]):
            flash('Todos os campos são obrigatórios para o ajuste.', 'danger')
            return redirect(url_for('stock_adjustment'))

        try:
            novo_estoque = int(novo_estoque_str)
            if novo_estoque < 0:
                raise ValueError("O novo estoque não pode ser negativo.")

            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Buscar dados atuais do produto
            cursor.execute(f"SELECT nome_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto,))
            product_data = cursor.fetchone()

            if not product_data:
                flash(f"Produto com código '{codigo_produto}' não encontrado.", 'danger')
                conn.close()
                return redirect(url_for('stock_adjustment'))

            nome_produto, estoque_sistema_registrado = product_data

            # Iniciar transação para garantir a integridade dos dados
            cursor.execute("BEGIN TRANSACTION")

            # 1. Atualizar o estoque na tabela principal
            cursor.execute(f"UPDATE {TABLE_PRODUTOS_ETRADE} SET estoque_sistema = ? WHERE codigo_produto = ?", (novo_estoque, codigo_produto))

            # 2. Registrar o log da alteração
            timestamp_atual = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(f"""
                INSERT INTO {TABLE_LOG_AJUSTES_ESTOQUE}
                (timestamp, codigo_produto, nome_produto, estoque_anterior, estoque_novo, motivo, usuario_id, usuario_username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp_atual, codigo_produto, nome_produto, estoque_sistema_registrado, novo_estoque, motivo, session.get('user_id'), session.get('username')))

            conn.commit()
            conn.close()

            flash(f"Estoque do produto '{nome_produto}' ajustado de {estoque_sistema_registrado} para {novo_estoque} com sucesso!", 'success')
            logger_app.info(f"Ajuste de estoque por '{session.get('username')}': Produto {codigo_produto}, de {estoque_sistema_registrado} para {novo_estoque}. Motivo: {motivo}")
            return redirect(url_for('stock_adjustment'))

        except ValueError as ve:
            flash(f"Erro de validação: {ve}", 'danger')
        except Exception as e:
            flash(f"Erro ao realizar o ajuste de estoque: {e}", 'danger')
            logger_app.error(f"Erro em stock_adjustment (POST): {e}", exc_info=True)
            if 'conn' in locals() and conn:
                conn.rollback() # Desfaz a transação em caso de erro
                conn.close()

        return redirect(url_for('stock_adjustment'))

    return render_template('stock_adjustment.html')

@app.route('/admin/stock_adjustment_log')
@login_required
def stock_adjustment_log():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT * FROM {TABLE_LOG_AJUSTES_ESTOQUE}
            ORDER BY timestamp DESC
        """)
        logs = cursor.fetchall()
        conn.close()
        return render_template('stock_adjustment_log.html', logs=logs)
    except Exception as e:
        logger_app.error(f"Erro ao buscar log de ajustes de estoque: {e}", exc_info=True)
        flash('Erro ao carregar o log de ajustes.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/price_history')
@login_required
def report_price_history():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT * FROM {TABLE_PRICE_HISTORY}
            ORDER BY timestamp DESC
        """)
        logs = cursor.fetchall()
        conn.close()
        return render_template('report_price_history.html', logs=logs)
    except Exception as e:
        logger_app.error(f"Erro ao buscar histórico de preços: {e}", exc_info=True)
        flash('Erro ao carregar o histórico de preços.', 'danger')
        return redirect(url_for('dashboard'))

# Função auxiliar para registrar alteração de preço
def log_price_change(codigo_produto, nome_produto, preco_anterior, preco_novo, user_id, username):
    """Registra uma alteração de preço no histórico."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(f"INSERT INTO {TABLE_PRICE_HISTORY} (timestamp, codigo_produto, nome_produto, preco_anterior, preco_novo, usuario_id, usuario_username) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (timestamp_now, codigo_produto, nome_produto, preco_anterior, preco_novo, user_id, username))
        conn.commit()
        conn.close()
        # Exemplo de onde esta função deveria ser chamada:
        # Quando você atualiza o preço de um produto, seja via automação (automate_etrade.py)
        # ou através de uma interface de edição de produto manual, você deve chamar:
        # log_price_change(codigo_do_produto, nome_do_produto, preco_antigo, novo_preco, session.get('user_id'), session.get('username'))
    except Exception as e:
        logger_app.error(f"Erro ao registrar alteração de preço para {codigo_produto}: {e}", exc_info=True)

@app.route('/admin/audit_log')
@login_required
def admin_audit_log():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_AUDIT_LOG} ORDER BY timestamp DESC")
        logs = cursor.fetchall()
        conn.close()
        return render_template('admin_audit_log.html', logs=logs)
    except Exception as e:
        logger_app.error(f"Erro ao buscar log de auditoria: {e}", exc_info=True)
        flash('Erro ao carregar o log de auditoria.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/feedback_reports')
@login_required
def admin_feedback_reports():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_FEEDBACK} ORDER BY timestamp DESC")
        feedbacks = cursor.fetchall()
        conn.close()
        return render_template('admin_feedback_reports.html', feedbacks=feedbacks)
    except Exception as e:
        logger_app.error(f"Erro ao buscar relatórios de feedback: {e}", exc_info=True)
        flash('Erro ao carregar os relatórios de feedback.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/feedback_reports/update/<int:feedback_id>', methods=['POST'])
@login_required
def update_feedback_report(feedback_id):
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    admin_response = request.form.get('admin_response')
    new_status = request.form.get('status')

    if not admin_response or not new_status:
        flash('A resposta e o novo status são obrigatórios.', 'danger')
        return redirect(url_for('admin_feedback_reports'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_user_id = session.get('user_id')
        admin_username = session.get('username')

        cursor.execute(f"""
            UPDATE {TABLE_FEEDBACK}
            SET status = ?,
                admin_response = ?,
                response_timestamp = ?,
                response_user_id = ?,
                response_username = ?
            WHERE id = ?
        """, (new_status, admin_response, timestamp_now, admin_user_id, admin_username, feedback_id))
        
        conn.commit()

        # Opcional: Notificar o usuário que enviou o feedback
        cursor.execute(f"SELECT user_id, subject FROM {TABLE_FEEDBACK} WHERE id = ?", (feedback_id,))
        feedback_info = cursor.fetchone()
        if feedback_info and feedback_info[0]:
            original_user_id, feedback_subject = feedback_info
            create_notification(
                original_user_id,
                f"Seu feedback '{feedback_subject[:30]}...' foi respondido.",
                'success',
                url_for('my_feedback')
            )

        conn.close()
        
        flash('Feedback respondido e atualizado com sucesso!', 'success')
        log_audit('feedback_response', f"Admin '{admin_username}' respondeu ao feedback ID {feedback_id}")

    except Exception as e:
        logger_app.error(f"Erro ao atualizar feedback ID {feedback_id}: {e}", exc_info=True)
        flash('Erro ao atualizar o feedback.', 'danger')
    return redirect(url_for('admin_feedback_reports'))

@app.route('/my_feedback')
@login_required
def my_feedback():
    """Página para o usuário visualizar seus próprios feedbacks e as respostas."""
    user_id = session.get('user_id')
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_FEEDBACK} WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
        feedbacks = cursor.fetchall()
        conn.close()
        return render_template('my_feedback.html', feedbacks=feedbacks)
    except Exception as e:
        logger_app.error(f"Erro ao buscar feedbacks do usuário {user_id}: {e}", exc_info=True)
        flash('Erro ao carregar seus feedbacks.', 'danger')
        return redirect(url_for('index'))

# New route for reporting issues/suggestions
@app.route('/report_issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        feedback_type = request.form.get('feedback_type')
        subject = request.form.get('subject')
        description = request.form.get('description')
        user_id = session.get('user_id')
        username = session.get('username')

        if not all([feedback_type, subject, description]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('report_issue.html')

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute(f"""
                INSERT INTO {TABLE_FEEDBACK} (timestamp, user_id, username, feedback_type, subject, description, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp_now, user_id, username, feedback_type, subject, description, 'pendente'))
            
            conn.commit()
            
            # Create in-app notification for all Admins
            cursor.execute(f"SELECT id FROM {TABLE_USUARIOS} WHERE cargo = 'Admin'")
            admin_users = cursor.fetchall()
            conn.close()

            for admin in admin_users:
                create_notification(
                    admin[0], 
                    f"Novo feedback de '{username}': {subject}", 
                    'info', 
                    url_for('admin_feedback_reports')
                )

            flash('Seu feedback foi enviado com sucesso! Agradecemos sua contribuição.', 'success')
            log_audit('feedback_submitted', f"Feedback enviado por '{username}': {subject}")
            return redirect(url_for('index'))
        except Exception as e:
            logger_app.error(f"Erro ao salvar feedback de '{username}': {e}", exc_info=True)
            flash('Ocorreu um erro ao enviar seu feedback. Tente novamente.', 'danger')

    return render_template('report_issue.html')

@app.route('/admin/transfer_stock', methods=['GET', 'POST'])
@login_required
def transfer_stock():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        flash('Funcionalidade de transferência de estoque ainda não implementada.', 'info')
        return redirect(url_for('transfer_stock'))

    return render_template('transfer_stock.html')

@app.route('/reports/inventory_value')
@login_required
def report_inventory_value():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT codigo_produto, nome_produto, estoque_sistema, preco, (estoque_sistema * preco) as valor_total FROM produtos_etrade WHERE estoque_sistema > 0 ORDER BY valor_total DESC")
        products = cursor.fetchall()
        total_inventory_value = sum(p['valor_total'] for p in products if p['valor_total'] is not None)
        conn.close()
        return render_template('report_inventory_value.html', products=products, total_inventory_value=total_inventory_value)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de valor de inventário: {e}", exc_info=True)
        flash('Erro ao carregar o relatório de valor de inventário.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/export_inventory_value_csv')
@login_required
def export_inventory_value_csv():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT codigo_produto, nome_produto, estoque_sistema, preco, (estoque_sistema * preco) as valor_total FROM produtos_etrade WHERE estoque_sistema > 0 ORDER BY valor_total DESC")
        products = cursor.fetchall()
        conn.close()

        si = io.StringIO()
        cw = csv.writer(si)
        
        # Header
        cw.writerow(['Codigo Produto', 'Nome Produto', 'Estoque Sistema', 'Preco Unitario', 'Valor Total'])
        
        # Rows
        for product in products:
            preco = product['preco'] if product['preco'] is not None else 0
            valor_total = product['valor_total'] if product['valor_total'] is not None else 0
            cw.writerow([
                product['codigo_produto'],
                product['nome_produto'],
                product['estoque_sistema'],
                f"{preco:.2f}".replace('.', ','),
                f"{valor_total:.2f}".replace('.', ',')
            ])

        output = si.getvalue()
        response = make_response(output)
        response.headers["Content-Disposition"] = "attachment; filename=relatorio_valor_inventario.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        logger_app.error(f"Erro ao exportar relatório de valor de inventário: {e}", exc_info=True)
        flash('Erro ao gerar o relatório de valor de inventário.', 'danger')
        return redirect(url_for('report_inventory_value'))

@app.route('/reports/export_sales_history_csv')
@login_required
def export_sales_history_csv():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT log.data_verificacao, log.codigo_produto, log.nome_produto, log.quantidade_vendida, etrade.preco
        FROM {TABLE_PRODUTOS_VENDIDOS_LOG} as log
        LEFT JOIN {TABLE_PRODUTOS_ETRADE} as etrade ON log.codigo_produto = etrade.codigo_produto
        WHERE log.status = 'processado' AND date(log.data_verificacao) BETWEEN ? AND ?
        ORDER BY log.data_verificacao DESC
    """, (start_date, end_date))
    sales_history = cursor.fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)

    # Escreve o cabeçalho
    cw.writerow(['Data da Venda', 'Codigo do Produto', 'Nome do Produto', 'Quantidade Vendida', 'Preco Unitario (Atual)', 'Valor Total'])

    # Escreve os dados
    for sale in sales_history:
        preco = sale['preco'] if sale['preco'] is not None else 0
        valor_total_item = sale['quantidade_vendida'] * preco
        cw.writerow([
            sale['data_verificacao'].split(' ')[0],
            sale['codigo_produto'],
            sale['nome_produto'],
            sale['quantidade_vendida'],
            f"{preco:.2f}".replace('.', ','), # Formata para CSV com vírgula decimal
            f"{valor_total_item:.2f}".replace('.', ',')
        ])

    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=historico_vendas_{start_date}_a_{end_date}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/reports/sales_history')
@login_required
def report_sales_history():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    start_date = request.args.get('start_date', (datetime.date.today() - datetime.timedelta(days=30)).isoformat())
    end_date = request.args.get('end_date', datetime.date.today().isoformat())

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Query modificada para buscar o preço atual do produto e calcular o valor da venda
        cursor.execute(f"""
            SELECT 
                log.data_verificacao,
                log.codigo_produto,
                log.nome_produto,
                log.quantidade_vendida,
                etrade.preco
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG} as log
            LEFT JOIN {TABLE_PRODUTOS_ETRADE} as etrade ON log.codigo_produto = etrade.codigo_produto
            WHERE log.status = 'processado' AND date(log.data_verificacao) BETWEEN ? AND ? 
            ORDER BY log.data_verificacao DESC
        """, (start_date, end_date))
        sales_history = cursor.fetchall()
        conn.close()

        # Calcula o valor total no backend para maior segurança e clareza
        total_value = 0
        for sale in sales_history:
            if sale['preco'] is not None:
                total_value += sale['quantidade_vendida'] * sale['preco']

        return render_template('report_sales_history.html', sales_history=sales_history, start_date=start_date, end_date=end_date, total_value=total_value)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de histórico de vendas: {e}", exc_info=True)
        flash('Erro ao carregar o relatório de histórico de vendas.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/stagnant_stock')
@login_required
def report_stagnant_stock():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    days_no_sales = request.args.get('days_no_sales', 90, type=int)
    
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Produtos que tiveram vendas no período
        cursor.execute(f"""
            SELECT DISTINCT codigo_produto
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG}
            WHERE data_verificacao >= date('now', '-' || ? || ' days')
        """, (days_no_sales,))
        products_with_recent_sales = {row['codigo_produto'] for row in cursor.fetchall()}

        # Produtos que tiveram entradas no período
        cursor.execute(f"""
            SELECT DISTINCT codigo_produto
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            WHERE timestamp >= date('now', '-' || ? || ' days')
        """, (days_no_sales,))
        products_with_recent_entries = {row['codigo_produto'] for row in cursor.fetchall()}

        # Todos os produtos com estoque > 0
        cursor.execute(f"""
            SELECT codigo_produto, nome_produto, estoque_sistema, preco, marca, classe
            FROM {TABLE_PRODUTOS_ETRADE}
            WHERE estoque_sistema > 0
        """)
        all_stocked_products = cursor.fetchall()
        conn.close()

        stagnant_products = []
        for product in all_stocked_products:
            if product['codigo_produto'] not in products_with_recent_sales and \
               product['codigo_produto'] not in products_with_recent_entries:
                stagnant_products.append(product)
        
        return render_template('report_stagnant_stock.html', 
                               stagnant_products=stagnant_products, 
                               days_no_sales=days_no_sales)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de estoque parado: {e}", exc_info=True)
        flash('Erro ao carregar o relatório de estoque parado.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/critical_stock')
@login_required
def report_critical_stock():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    critical_threshold = request.args.get('threshold', 5, type=int) # Limite padrão de 5 unidades

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT codigo_produto, nome_produto, estoque_sistema, preco, marca, classe FROM {TABLE_PRODUTOS_ETRADE} WHERE estoque_sistema <= ? AND estoque_sistema > 0 ORDER BY estoque_sistema ASC", (critical_threshold,))
        critical_products = cursor.fetchall()
        conn.close()
        return render_template('report_critical_stock.html', critical_products=critical_products, threshold=critical_threshold)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de estoque crítico: {e}", exc_info=True)
        flash('Erro ao carregar o relatório de estoque crítico.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/sales_velocity')
@login_required
def report_sales_velocity():
    """Relatório de velocidade de vendas dos produtos."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    period_days = request.args.get('days', 30, type=int)

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = f"""
            SELECT
                p.nome_produto,
                p.codigo_produto,
                SUM(l.quantidade_vendida) as total_vendido,
                printf("%.2f", CAST(SUM(l.quantidade_vendida) AS REAL) / ?) as media_diaria
            FROM {TABLE_PRODUTOS_VENDIDOS_LOG} l
            JOIN {TABLE_PRODUTOS_ETRADE} p ON l.codigo_produto = p.codigo_produto
            WHERE l.data_verificacao >= date('now', '-' || ? || ' days') AND l.status = 'processado'
            GROUP BY p.codigo_produto, p.nome_produto
            ORDER BY total_vendido DESC
        """
        cursor.execute(query, (period_days, period_days))
        sales_data = cursor.fetchall()
        conn.close()
        
        return render_template('report_sales_velocity.html', sales_data=sales_data, period_days=period_days)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de velocidade de vendas: {e}", exc_info=True)
        flash('Erro ao carregar o relatório.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports/stock_rupture')
@login_required
def report_stock_rupture():
    """Relatório de rupturas de estoque (backstock negativo)."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(f"""
            SELECT timestamp, codigo_produto, nome_produto_informado, estoque_sistema_no_momento, 
                   qtd_prateleira_informada, backstock_calculado, usuario_username
            FROM {TABLE_LOG_ENTRADAS_PRATELEIRA} 
            WHERE backstock_calculado < 0 
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        rupture_data = cursor.fetchall()
        conn.close()
        
        return render_template('report_stock_rupture.html', ruptures=rupture_data)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de ruptura de estoque: {e}", exc_info=True)
        flash('Erro ao carregar o relatório de rupturas.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/api/dashboard_charts')
@login_required
def api_dashboard_charts():
    """Fornece dados formatados para os gráficos do dashboard."""
    if session.get('cargo') != 'Admin':
        return jsonify({'error': 'Acesso não autorizado'}), 403

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Dados para o gráfico de entradas por dia (últimos 7 dias)
        cursor.execute(f"""
            SELECT date(timestamp) as dia, COUNT(id) as total 
        """)
        entradas_por_dia = cursor.fetchall()

        # Dados para o gráfico de top 5 produtos
        cursor.execute(f"""
            SELECT nome_produto_informado, COUNT(id) as total FROM {TABLE_LOG_ENTRADAS_PRATELEIRA}
            GROUP BY nome_produto_informado ORDER BY total DESC LIMIT 5
        """)
        top_produtos_chart = cursor.fetchall()

        conn.close()

        return jsonify({
            'entradas_por_dia': {'labels': [row[0] for row in entradas_por_dia], 'data': [row[1] for row in entradas_por_dia]},
            'top_produtos': {'labels': [row[0] for row in top_produtos_chart], 'data': [row[1] for row in top_produtos_chart]}
        })
    except Exception as e:
        logger_app.error(f"Erro ao gerar dados para os gráficos do dashboard: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao buscar dados para os gráficos'}), 500

@app.route('/api/notifications')
@login_required
def get_notifications():
    user_id = session.get('user_id')
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get unread notifications for the user
        cursor.execute(f"""
            SELECT id, timestamp, message, type, link
            FROM {TABLE_NOTIFICATIONS}
            WHERE user_id = ? AND is_read = 0
            ORDER BY timestamp DESC
            LIMIT 10
        """, (user_id,))
        notifications = [dict(row) for row in cursor.fetchall()]

        # Get unread count
        cursor.execute(f"SELECT COUNT(id) FROM {TABLE_NOTIFICATIONS} WHERE user_id = ? AND is_read = 0", (user_id,))
        unread_count = cursor.fetchone()[0]
        
        conn.close()

        return jsonify({
            'notifications': notifications,
            'unread_count': unread_count
        })
    except Exception as e:
        logger_app.error(f"Erro ao buscar notificações para user_id {user_id}: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao buscar notificações'}), 500

@app.route('/api/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_as_read(notification_id):
    user_id = session.get('user_id')
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        # Mark a specific notification as read, ensuring it belongs to the current user
        cursor.execute(f"UPDATE {TABLE_NOTIFICATIONS} SET is_read = 1 WHERE id = ? AND user_id = ?", (notification_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Notificação marcada como lida.'}), 200
    except Exception as e:
        logger_app.error(f"Erro ao marcar notificação {notification_id} como lida: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao marcar notificação como lida'}), 500

@app.route('/api/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_as_read():
    user_id = session.get('user_id')
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(f"UPDATE {TABLE_NOTIFICATIONS} SET is_read = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Todas as notificações foram marcadas como lidas.'}), 200
    except Exception as e:
        logger_app.error(f"Erro ao marcar todas as notificações como lidas para user_id {user_id}: {e}", exc_info=True)
        return jsonify({'error': 'Erro ao marcar todas as notificações como lidas'}), 500

@app.route('/sales_analysis')
@login_required
def sales_analysis():
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    analysis_results = []
    sales_period_days = SALES_ANALYSIS_PERIOD_DAYS # Período padrão para cálculo de vendas

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Obter todos os produtos do E-Trade
        cursor.execute(f"SELECT codigo_produto, nome_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE}")
        all_products = cursor.fetchall()
        conn.close()

        for product in all_products:
            codigo_produto, nome_produto, estoque_sistema = product
            days_of_stock = calculate_days_of_stock_remaining(codigo_produto, estoque_sistema, sales_period_days)
            
            analysis_results.append({
                'codigo_produto': codigo_produto,
                'nome_produto': nome_produto,
                'estoque_sistema': estoque_sistema,
                'dias_de_estoque': f"{days_of_stock:.2f}" if days_of_stock is not None else "N/A"
            })
        analysis_results.sort(key=lambda x: x['nome_produto']) # Sort for better readability
    except Exception as e:
        logger_app.error(f"Erro ao gerar análise de vendas: {e}", exc_info=True)
        flash(f'Erro ao carregar análise de vendas: {e}', 'danger')

    return render_template('sales_analysis.html', analysis_results=analysis_results, sales_period_days=sales_period_days)

@app.route('/test-mobile')
def test_mobile():
    return "Conexao OK do Flask!"

@app.route('/test_camera')
@login_required
def test_camera():
    """Página para testar o acesso à câmera do dispositivo."""
    return render_template('test_camera.html')

@app.route('/scan_ean', methods=['POST'])
def scan_ean_route():
    data = request.get_json()
    ean_code = data.get('ean_code')

    if not ean_code:
        return jsonify({'status': 'error', 'message': 'Código EAN não fornecido.'}), 400

    logger_app.info(f"Recebida requisição para buscar EAN: {ean_code}")
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(f"SELECT codigo_produto, nome_produto FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_ean = ?", (ean_code,))
        product_data = cursor.fetchone()
        conn.close()

        if product_data:
            logger_app.info(f"EAN '{ean_code}' encontrado: Código {product_data[0]}, Nome: {product_data[1]}")
            return jsonify({
                'status': 'success',
                'codigo_produto': product_data[0],
                'nome_produto': product_data[1]
            })
        else:
            logger_app.info(f"EAN '{ean_code}' não encontrado no banco de dados.")
            return jsonify({'status': 'not_found', 'message': f"Produto com EAN '{ean_code}' não encontrado."}), 404
    except Exception as e:
        logger_app.error(f"Erro ao buscar EAN '{ean_code}' no banco de dados: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f"Erro interno ao buscar EAN: {str(e)}"}), 500

@app.route('/api/product_search')
@login_required
def api_product_search():
    """
    Fornece sugestões de produtos para um campo de busca unificado.
    Busca por:
    1. Nome do produto (autocomplete, case-insensitive).
    2. Código do produto (correspondência exata ou parcial no início).
    3. Últimos 5 dígitos do código de barras (EAN).
    """
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.create_function("unaccent", 1, remove_accents) # Permite busca sem acentos
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Prepara os termos de busca
        # Busca por nome agora é case-insensitive e accent-insensitive
        nome_like = f"%{remove_accents(query.lower())}%"
        codigo_like = f"{query}%"
        ean_suffix_like = f"%{query}"

        # Constrói a cláusula WHERE dinamicamente
        where_clauses = [
            "unaccent(LOWER(nome_produto)) LIKE :nome_like",
            "codigo_produto LIKE :codigo_like"
        ]
        params = {
            "nome_like": nome_like,
            "codigo_like": codigo_like,
            "query": query
        }

        # Adiciona a busca por EAN apenas se a query for 5 dígitos numéricos
        if len(query) == 5 and query.isdigit():
            where_clauses.append("codigo_ean LIKE :ean_suffix_like")
            params["ean_suffix_like"] = ean_suffix_like

        where_sql = " OR ".join(where_clauses)

        # A ordenação dá prioridade para correspondências exatas de código,
        # depois para códigos que começam com a busca, e finalmente por nome.
        sql_query = f"""
            SELECT codigo_produto, nome_produto, estoque_sistema, codigo_ean
            FROM {TABLE_PRODUTOS_ETRADE}
            WHERE {where_sql}
            ORDER BY
                CASE WHEN codigo_produto = :query THEN 0 ELSE 3 END,
                CASE WHEN codigo_produto LIKE :codigo_like THEN 1 ELSE 3 END,
                CASE WHEN unaccent(LOWER(nome_produto)) LIKE :nome_like THEN 2 ELSE 3 END,
                nome_produto
            LIMIT 15
        """

        cursor.execute(sql_query, params)
        products = cursor.fetchall()
        conn.close()

        # Formata a saída para o frontend
        results = []
        for product in products:
            results.append({
                'label': f"{product['nome_produto']} (Cód: {product['codigo_produto']})", # Texto da sugestão
                'nome': product['nome_produto'],
                'codigo': product['codigo_produto'],
                'estoque': product['estoque_sistema']
            })
    except Exception as e:
        logger_app.error(f"Erro na busca de produtos por API para '{query}': {e}", exc_info=True)
        return jsonify([]) # Retorna lista vazia em caso de erro para não quebrar o frontend

    return jsonify(results)

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    """Página para criar e visualizar anotações de produtos."""
    user_id = session.get('user_id')
    is_admin = session.get('cargo') == 'Admin'

    if request.method == 'POST':
        codigo_produto = request.form.get('codigo_produto')
        anotacao = request.form.get('anotacao')

        if not all([codigo_produto, anotacao]):
            flash('É necessário selecionar um produto e escrever uma anotação.', 'danger')
            return redirect(url_for('notes'))

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Busca o nome do produto para salvar junto com a anotação
            cursor.execute(f"SELECT nome_produto FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto,))
            product = cursor.fetchone()
            if not product:
                flash('Produto selecionado não foi encontrado no banco de dados.', 'danger')
                conn.close()
                return redirect(url_for('notes'))
            
            nome_produto = product[0]
            timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute(f"""
                INSERT INTO {TABLE_ANOTACOES} (timestamp, user_id, username, codigo_produto, nome_produto, anotacao)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp_now, user_id, session.get('username'), codigo_produto, nome_produto, anotacao))
            
            conn.commit()
            conn.close()
            flash('Anotação salva com sucesso!', 'success')
            log_audit('note_created', f"Anotação criada para o produto '{codigo_produto}' por '{session.get('username')}'")

        except Exception as e:
            logger_app.error(f"Erro ao salvar anotação: {e}", exc_info=True)
            flash('Ocorreu um erro ao salvar a anotação.', 'danger')
        
        return redirect(url_for('notes'))

    # Lógica para GET
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if is_admin:
            cursor.execute(f"SELECT * FROM {TABLE_ANOTACOES} ORDER BY timestamp DESC")
        else:
            cursor.execute(f"SELECT * FROM {TABLE_ANOTACOES} WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
        
        user_notes = cursor.fetchall()
        conn.close()
        return render_template('notes.html', notes=user_notes)
    except Exception as e:
        logger_app.error(f"Erro ao carregar anotações: {e}", exc_info=True) # Mantém o registro de erro
        flash('Erro ao carregar anotações.', 'danger')
        return render_template('notes.html', notes=[])

@app.route('/stock_correction', methods=['GET', 'POST'])
@login_required
def stock_correction():
    """Página para apontar e visualizar divergências de estoque."""
    user_id = session.get('user_id')
    is_admin = session.get('cargo') == 'Admin'

    if request.method == 'POST':
        codigo_produto = request.form.get('codigo_produto')
        qtd_prateleira_str = request.form.get('qtd_prateleira')
        qtd_estoque_str = request.form.get('qtd_estoque')

        if not all([codigo_produto, qtd_prateleira_str, qtd_estoque_str]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return redirect(url_for('stock_correction'))

        try:
            qtd_prateleira = int(qtd_prateleira_str)
            qtd_estoque = int(qtd_estoque_str)
            total_contado = qtd_prateleira + qtd_estoque

            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Busca dados atuais do produto para registrar
            cursor.execute(f"SELECT nome_produto, estoque_sistema FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto,))
            product = cursor.fetchone()
            if not product:
                flash('Produto selecionado não foi encontrado.', 'danger')
                conn.close()
                return redirect(url_for('stock_correction'))

            nome_produto, estoque_sistema_registrado = product
            diferenca = total_contado - (estoque_sistema_registrado or 0)
            timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute(f"""
                INSERT INTO {TABLE_STOCK_CORRECTION_LOG} (
                    timestamp, user_id, username, codigo_produto, nome_produto,
                    estoque_sistema_registrado, qtd_prateleira_contada, qtd_estoque_contado,
                    total_contado, diferenca, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp_now, user_id, session.get('username'), codigo_produto, nome_produto,
                estoque_sistema_registrado, qtd_prateleira, qtd_estoque,
                total_contado, diferenca, 'pendente'
            ))

            conn.commit()
            conn.close()
            flash(f'Apontamento de divergência para "{nome_produto}" salvo com sucesso!', 'success')
            log_audit('stock_correction_log', f"Apontamento de divergência para '{codigo_produto}' por '{session.get('username')}'")

        except ValueError as ve:
            flash(f"Erro de validação: {ve}", 'danger')
        except Exception as e:
            logger_app.error(f"Erro ao salvar apontamento de estoque: {e}", exc_info=True)
            flash('Ocorreu um erro ao salvar o apontamento.', 'danger')

        return redirect(url_for('stock_correction'))

    # Lógica para GET
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Admins veem todos os pendentes, usuários veem apenas os seus
        if is_admin:
            cursor.execute(f"SELECT * FROM {TABLE_STOCK_CORRECTION_LOG} WHERE status = 'pendente' ORDER BY timestamp DESC")
        else:
            cursor.execute(f"SELECT * FROM {TABLE_STOCK_CORRECTION_LOG} WHERE user_id = ? AND status = 'pendente' ORDER BY timestamp DESC", (user_id,))

        pending_corrections = cursor.fetchall()
        conn.close()
        return render_template('stock_correction.html', corrections=pending_corrections)
    except Exception as e:
        logger_app.error(f"Erro ao carregar apontamentos de estoque: {e}", exc_info=True)
        flash('Erro ao carregar apontamentos de estoque.', 'danger')
        return render_template('stock_correction.html', corrections=[])

@app.route('/stock_correction/export')
@login_required
def export_stock_corrections():
    """Gera uma página de relatório para impressão com as correções pendentes."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_STOCK_CORRECTION_LOG} WHERE status = 'pendente' ORDER BY nome_produto ASC")
        corrections = cursor.fetchall()
        conn.close()

        report_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        return render_template('stock_correction_report.html', corrections=corrections, report_time=report_time)
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de correção de estoque: {e}", exc_info=True)
        flash('Erro ao gerar o relatório para exportação.', 'danger')
        return redirect(url_for('stock_correction'))

@app.route('/log_lost_sale', methods=['GET', 'POST'])
@login_required
def log_lost_sale():
    """Página para registrar uma venda perdida (cliente saiu sem comprar)."""
    if request.method == 'POST':
        produto_interesse = request.form.get('produto_interesse')
        motivo = request.form.get('motivo')
        contato_cliente = request.form.get('contato_cliente')

        if not produto_interesse or not motivo:
            flash('Os campos "Produto de Interesse" e "Motivo" são obrigatórios.', 'danger')
            return redirect(url_for('log_lost_sale'))

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            nome_responsavel = session.get('nome_planilha', session.get('username'))
            
            cursor.execute(f"""
                INSERT INTO {TABLE_LOST_SALES_LOG} (timestamp, user_id, username, loja, produto_interesse, motivo, contato_cliente)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp_now, session.get('user_id'), nome_responsavel,
                session.get('loja'), produto_interesse, motivo, contato_cliente
            ))
            
            conn.commit()
            conn.close()
            flash('Registro de venda perdida salvo com sucesso!', 'success')
            log_audit('lost_sale_logged', f"Venda perdida registrada por '{session.get('username')}' para o produto '{produto_interesse}'")
        except Exception as e:
            logger_app.error(f"Erro ao salvar registro de venda perdida: {e}", exc_info=True)
            flash('Ocorreu um erro ao salvar o registro.', 'danger')
        
        return redirect(url_for('log_lost_sale'))

    return render_template('log_lost_sale.html')

@app.route('/admin/lost_sales_report')
@login_required
def lost_sales_report():
    """Painel de análise de vendas perdidas para administradores."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    report_data = {
        'total_count': 0,
        'reasons_chart': {'labels': [], 'data': []},
        'top_products': [],
        'by_store': []
    }

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.create_function("unaccent", 1, remove_accents) # Registra a função para remover acentos
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total de registros
        cursor.execute(f"SELECT COUNT(id) FROM {TABLE_LOST_SALES_LOG}")
        report_data['total_count'] = cursor.fetchone()[0]

        # Agrupamento de motivos (case-insensitive, sem acentos e sem espaços extras)
        cursor.execute(f"""
            SELECT TRIM(unaccent(LOWER(motivo))) as motivo_standard, COUNT(id) as count
            FROM {TABLE_LOST_SALES_LOG}
            GROUP BY motivo_standard
            ORDER BY count DESC LIMIT 10
        """)
        reasons = cursor.fetchall()
        report_data['reasons_chart'] = {
            'labels': [row['motivo_standard'].capitalize() for row in reasons],
            'data': [row['count'] for row in reasons]
        }

        # Top produtos de interesse
        cursor.execute(f"SELECT produto_interesse, COUNT(id) as count FROM {TABLE_LOST_SALES_LOG} GROUP BY LOWER(produto_interesse) ORDER BY count DESC LIMIT 10")
        report_data['top_products'] = cursor.fetchall()

        # Contagem por loja
        cursor.execute(f"SELECT loja, COUNT(id) as count FROM {TABLE_LOST_SALES_LOG} GROUP BY loja ORDER BY count DESC")
        report_data['by_store'] = cursor.fetchall()

        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao gerar relatório de vendas perdidas: {e}", exc_info=True)
        flash('Erro ao gerar o relatório de vendas perdidas.', 'danger')

    return render_template('lost_sales_report.html', data=report_data)

@app.route('/admin/lost_sales_report/export')
@login_required
def export_lost_sales_report():
    """Gera uma página de relatório para impressão com os dados de vendas perdidas."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_LOST_SALES_LOG} ORDER BY timestamp DESC")
        all_logs = cursor.fetchall()
        conn.close()
        report_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        return render_template('lost_sales_report_export.html', logs=all_logs, report_time=report_time)
    except Exception as e:
        logger_app.error(f"Erro ao exportar relatório de vendas perdidas: {e}", exc_info=True)
        flash('Erro ao gerar o relatório para exportação.', 'danger')
        return redirect(url_for('lost_sales_report'))

@app.route('/admin/lost_sales_log/delete/<int:log_id>', methods=['POST'])
@login_required
def delete_lost_sale_log(log_id):
    """Remove um registro de venda perdida do log."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Busca o item antes de deletar para logar mais detalhes
        cursor.execute(f"SELECT produto_interesse FROM {TABLE_LOST_SALES_LOG} WHERE id = ?", (log_id,))
        item_to_delete = cursor.fetchone()

        cursor.execute(f"DELETE FROM {TABLE_LOST_SALES_LOG} WHERE id = ?", (log_id,))
        
        if cursor.rowcount > 0:
            conn.commit()
            flash('Registro de venda perdida removido com sucesso.', 'success')
            produto_interesse = item_to_delete[0] if item_to_delete else 'desconhecido'
            log_audit('lost_sale_deleted', f"Registro de venda perdida ID {log_id} (Produto: {produto_interesse}) removido por '{session.get('username')}'")
        else:
            flash('Registro não encontrado.', 'warning')
            
        conn.close()
    except Exception as e:
        logger_app.error(f"Erro ao remover registro de venda perdida ID {log_id}: {e}", exc_info=True)
        flash('Erro ao remover o registro.', 'danger')

    return redirect(url_for('export_lost_sales_report'))

# --- Funções e Rotas para a Nova Lógica de Produção ---

def extract_weight_from_name(product_name):
    """
    Extrai o peso (em kg) do nome de um produto.
    Ex: "RAÇÃO 50KG" -> 50.0, "MILHO 2,86KG" -> 2.86
    Retorna o peso como float ou None se não encontrar.
    """
    if not isinstance(product_name, str):
        return None
    
    # Tenta encontrar padrões como "50KG", "25 KG", "2,86kg", "30kilos"
    match = re.search(r'(\d+[\.,]?\d*)\s*(kg|kilos|kilo)', product_name, re.IGNORECASE)
    
    if match:
        try:
            # Pega o número, substitui vírgula por ponto e converte para float
            weight_str = match.group(1).replace(',', '.')
            return float(weight_str)
        except (ValueError, IndexError):
            return None
    return None

@app.route('/api/calculate_production', methods=['POST'])
@login_required
def api_calculate_production():
    """
    API para calcular a quantidade de pacotes menores a partir de um saco maior.
    Recebe os nomes dos produtos e retorna o cálculo.
    """
    data = request.get_json()
    nome_fracionado = data.get('nome_fracionado')
    nome_origem = data.get('nome_origem')

    if not nome_fracionado or not nome_origem:
        return jsonify({'error': 'Nomes dos produtos fracionado e de origem são obrigatórios.'}), 400

    peso_fracionado = extract_weight_from_name(nome_fracionado)
    peso_origem = extract_weight_from_name(nome_origem)

    if peso_fracionado is None:
        return jsonify({'error': f'Não foi possível identificar o peso do produto fracionado: "{nome_fracionado}". Verifique o cadastro (ex: NOME 2.5KG).'}), 400
    if peso_origem is None:
        return jsonify({'error': f'Não foi possível identificar o peso do produto de origem: "{nome_origem}". Verifique o cadastro (ex: NOME 50KG).'}), 400
    
    if peso_fracionado <= 0:
        return jsonify({'error': 'O peso do produto fracionado deve ser maior que zero.'}), 400

    try:
        qtd_produzida = int(peso_origem // peso_fracionado)
        sobra = peso_origem % peso_fracionado
        return jsonify({
            'success': True,
            'quantidade_calculada': qtd_produzida,
            'peso_origem': peso_origem,
            'peso_fracionado': peso_fracionado,
            'sobra_kg': round(sobra, 2)
        })
    except Exception as e:
        logger_app.error(f"Erro no cálculo de produção: {e}", exc_info=True)
        return jsonify({'error': f'Erro interno ao calcular: {e}'}), 500

@app.route('/request_production', methods=['GET', 'POST'])
@login_required
def request_production():
    if request.method == 'POST':
        try:
            # Coleta de dados do formulário
            codigo_fracionado = request.form.get('codigo_produto_fracionado')
            nome_fracionado = request.form.get('nome_produto_fracionado')
            qtd_prateleira = request.form.get('qtd_prateleira', type=int)
            codigo_origem = request.form.get('codigo_produto_origem')
            nome_origem = request.form.get('nome_produto_origem')
            qtd_calculada = request.form.get('quantidade_calculada', type=int)

            # Validação básica
            if not all([codigo_fracionado, nome_fracionado, qtd_prateleira is not None, codigo_origem, nome_origem, qtd_calculada is not None]):
                flash('Todos os campos são obrigatórios.', 'danger')
                return redirect(url_for('request_production'))

            # --- DEMONSTRATION MODE: Simulate success without Google Sheets ---
            solicitante = session.get('nome_planilha', session.get('username'))
            status_inicial = 'DEMO_PENDENTE' # Use a demo status

            # Log to local DB for demonstration purposes
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            timestamp_db = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(f"""
                INSERT INTO {TABLE_LOG_PRODUCAO} (
                    timestamp, codigo_produto_fracionado, nome_produto_fracionado,
                    codigo_produto_origem, nome_produto_origem, qtd_prateleira_informada,
                    qtd_produzida_calculada, usuario_id, usuario_username, loja, status_planilha
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp_db, codigo_fracionado, nome_fracionado,
                codigo_origem, nome_origem, qtd_prateleira,
                qtd_calculada, session.get('user_id'), solicitante,
                session.get('loja'), status_inicial
            ))
            conn.commit()
            conn.close()

            log_audit('production_request', f"Solicitação de produção para '{nome_fracionado}' por '{session.get('username')}'")
            flash(f'DEMO: Solicitação de produção para "{nome_fracionado}" seria enviada para a planilha de produção com status "{status_inicial}".', 'success')
            # --- END DEMONSTRATION MODE ---

        except Exception as e:
            logger_app.error(f"Erro ao processar solicitação de produção: {e}", exc_info=True)
            flash(f"Ocorreu um erro inesperado: {e}", 'danger')
        
        return redirect(url_for('request_production'))

    # Lógica para GET
    return render_template('request_production.html')

@app.route('/api/agent/submit_data', methods=['POST'])
def agent_submit_data():
    """
    Endpoint para o agente cliente enviar os dados coletados da automação.
    """
    # Verificação de segurança
    secret_from_agent = request.headers.get('X-Agent-Secret')
    if not secret_from_agent or secret_from_agent != AGENT_SECRET_KEY:
        logger_app.warning(f"Tentativa de acesso não autorizado ao endpoint de submissão de dados do IP: {request.remote_addr}")
        return jsonify({'error': 'Acesso não autorizado'}), 403

    data = request.get_json()
    if not data or 'data' not in data:
        return jsonify({'error': 'Nenhum dado fornecido no payload.'}), 400

    success, message = process_etrade_data(data['data'])

    if success:
        return jsonify({'status': 'success', 'message': f'Dados processados com sucesso no servidor. Detalhes: {message}'}), 200
    else:
        return jsonify({'status': 'error', 'message': f'Falha ao processar dados no servidor. Detalhes: {message}'}), 500

@app.route('/admin/log_viewer')
@login_required
def log_viewer():
    """Visualizador de logs - Apenas para administradores."""
    if session.get('cargo') != 'Admin':
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))

    status_file = "automation_status.txt"
    terminal_output = "" 
    error_message = ""

    try:
        with open(status_file, "r", encoding="utf-8") as f:  # Especifica encoding para evitar erros
            terminal_output = f.read()
    except FileNotFoundError:
        error_message = "Arquivo de status da automação não encontrado."
        logger_app.warning(error_message)
    except Exception as e:
        error_message = f"Erro ao ler o arquivo de status da automação: {e}"
        logger_app.error(error_message, exc_info=True)

    #  Se o arquivo estiver vazio, mostra uma mensagem padrão
    if not terminal_output and not error_message:
        terminal_output = "Aguardando informações da automação..."

    return render_template('log_viewer.html', terminal_output=terminal_output, error_message=error_message)




if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        if NGROK_STATIC_DOMAIN:
            ngrok_command = f'ngrok http 5000 --domain "{NGROK_STATIC_DOMAIN}"'
            logger_app.info(f"Domínio estático configurado. A aplicação estará acessível em: https://{NGROK_STATIC_DOMAIN}")
        else:
            ngrok_command = 'ngrok http 5000'
            logger_app.warning("Nenhum domínio estático do ngrok configurado. A URL será dinâmica e precisará ser obtida na janela do ngrok.")

        try:
            logger_app.info(f"Tentando iniciar o ngrok em uma nova janela com o comando: {ngrok_command}")
            # ALTERAÇÃO: Executa o ngrok de forma totalmente oculta.
            # cmd.exe /c: Executa o comando e fecha o terminal (que já está invisível).
            # creationflags=0x08000000: Esta é a flag CREATE_NO_WINDOW do Windows, que impede a criação de uma janela de console.
            subprocess.Popen(f'cmd.exe /c "{ngrok_command}"', creationflags=0x08000000)
            logger_app.info("Comando para iniciar o ngrok enviado em segundo plano (oculto).")
        except FileNotFoundError:
            logger_app.error("Erro: 'ngrok.exe' ou 'cmd.exe' não foi encontrado. Certifique-se de que o ngrok está instalado e no seu PATH do sistema.")
        except Exception as e:
            logger_app.error(f"Erro ao tentar iniciar o ngrok: {e}")

    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False) # use_reloader=False para evitar múltiplas sessões do ngrok
