import requests
import time
import subprocess
import os
import sys
import logging
import configparser
from logging.handlers import RotatingFileHandler

# --- Configuração ---

def get_base_path():
    """Retorna o caminho base para os arquivos, funcionando tanto em modo script quanto em .exe compilado."""
    if getattr(sys, 'frozen', False):
        # Se estiver rodando como um .exe (compilado pelo PyInstaller)
        return os.path.dirname(sys.executable)
    else:
        # Se estiver rodando como um script .py normal
        return os.path.dirname(os.path.abspath(__file__))

BASE_PATH = get_base_path()
CONFIG_FILE_PATH = os.path.join(BASE_PATH, 'agent_config.ini')

# --- Configuração de Logging Robusta ---
LOG_DIR = os.path.join(os.getenv('APPDATA'), 'AgroKaSystem')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'agent.log')

# Usamos RotatingFileHandler para evitar que o arquivo de log cresça indefinidamente.
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=2) # 5MB por arquivo, mantém 2 backups

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - AGENT - %(levelname)s - %(message)s',
    handlers=[
        handler,
        logging.StreamHandler()
    ]
)

def load_config():
    """Carrega as configurações do arquivo agent_config.ini."""
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE_PATH):
        logging.critical(f"ARQUIVO DE CONFIGURAÇÃO NÃO ENCONTRADO EM: {CONFIG_FILE_PATH}")
        logging.critical("Crie o arquivo 'agent_config.ini' no mesmo diretório do executável com as seções [Agent], ServerURL e SecretKey.")
        time.sleep(30) # Pausa para o usuário poder ler a mensagem de erro no log
        sys.exit(1) # Encerra o agente se o arquivo de config não existe

    config.read(CONFIG_FILE_PATH)
    return config['Agent']

def send_data_to_server(data, server_url, headers):
    """Envia os dados coletados para o servidor processar."""
    try:
        logging.info("Enviando dados coletados para o servidor...")
        response = requests.post(
            f"{server_url}/api/agent/submit_data",
            headers=headers,
            json={'data': data},
            timeout=60 # Timeout maior para envio de dados
        )
        response.raise_for_status()
        logging.info(f"Servidor respondeu com sucesso: {response.json().get('message')}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Falha ao enviar dados para o servidor: {e}")
        return False

def run_automation_task():
    """Inicia o script de automação do E-Trade, aguarda sua conclusão e loga o resultado."""
    try:
        # O script de automação deve estar na mesma pasta que o .exe do agente
        script_to_run = os.path.join(BASE_PATH, "automate_etrade.py")
        if not os.path.exists(script_to_run):
            logging.error(f"O script de automação '{script_to_run}' não foi encontrado.")
            return

        logging.info(f"EXECUTANDO o script de automação: {script_to_run}. O agente aguardará a conclusão.")
        
        # Usamos 'run' para aguardar a conclusão e capturar a saída e o status.
        result = subprocess.run(
            [sys.executable, script_to_run], 
            capture_output=True, 
            text=True, 
            check=False, # Não lança exceção se o script falhar
            encoding='utf-8', errors='replace' # Melhora o tratamento de caracteres especiais
        )

        # Loga a saída padrão e de erro do script de automação para depuração
        if result.stdout:
            logging.info(f"Saída do script de automação:\n--- INÍCIO SAÍDA ---\n{result.stdout.strip()}\n--- FIM SAÍDA ---")
        if result.stderr:
            logging.warning(f"Saída de erro do script de automação:\n--- INÍCIO ERRO ---\n{result.stderr.strip()}\n--- FIM ERRO ---")

        if result.returncode == 0:
            logging.info("Script de automação concluído com SUCESSO. Coletando dados...")
            return result.stdout # Retorna os dados coletados
        else:
            logging.error(f"Script de automação concluído com FALHA (código de saída: {result.returncode}). Verifique os logs acima.")
            return None

    except Exception as e:
        logging.error(f"Falha crítica ao tentar executar a tarefa de automação: {e}", exc_info=True)

def main():
    """Loop principal do agente para verificar tarefas."""
    logging.info("="*50)
    logging.info("INICIANDO AGENTE AGROKA SYSTEM")
    logging.info(f"Caminho base detectado: {BASE_PATH}")
    
    config = load_config()
    server_url = config.get('ServerURL', 'http://127.0.0.1:5000') # Fallback para localhost
    agent_secret_key = config.get('SecretKey', 'change-me')
    polling_interval = config.getint('PollingIntervalSeconds', 10)

    logging.info(f"Agente configurado. Verificando o servidor em {server_url} a cada {polling_interval} segundos.")
    headers = {
        'X-Agent-Secret': agent_secret_key
    }

    while True:
        try:
            logging.debug("Verificando por novas tarefas...")
            response = requests.get(f"{server_url}/api/agent/get_task", headers=headers, timeout=15)
            response.raise_for_status() # Lança um erro para status 4xx/5xx

            task_data = response.json()
            if task_data.get('task') == 'run_etrade_automation':
                logging.info("Tarefa 'run_etrade_automation' recebida do servidor.")
                collected_data = run_automation_task()

                # Verificação robusta para garantir que dados válidos sejam enviados.
                if collected_data and collected_data.strip():
                    logging.info("Dados válidos coletados. Enviando para o servidor...")
                    # Envia os dados para o servidor
                    send_data_to_server(collected_data, server_url, headers)
                elif collected_data is not None: # String vazia ou apenas com espaços
                    logging.warning("Automação concluída, mas nenhum dado útil foi coletado (resultado vazio). Não será enviado ao servidor.")
                else: # Retorno foi None, indicando falha no script
                    logging.error("A tarefa de automação falhou explicitamente e não retornou dados.")

        except requests.exceptions.RequestException as e:
            logging.warning(f"Não foi possível conectar ao servidor: {e}")
        except Exception as e:
            logging.error(f"Ocorreu um erro inesperado no loop principal: {e}", exc_info=True)

        time.sleep(polling_interval)

if __name__ == "__main__":
    main()