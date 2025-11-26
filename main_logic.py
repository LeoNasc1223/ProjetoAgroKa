import sqlite3
import os
import datetime
import logging
from config import (
    DATABASE_FILE, TABLE_PRODUTOS_ETRADE, TABLE_PRODUTOS_VENDIDOS_LOG,
    TOP_SELLING_DAYS, TOP_SELLING_COUNT, SALES_ANALYSIS_PERIOD_DAYS
)

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Usar um logger específico para o módulo



def get_top_selling_products():
    """
    Consulta o log de produtos vendidos para identificar os produtos mais vendidos
    em um período recente.
    Retorna um conjunto (set) de códigos de produto.
    """
    top_sellers = set()
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Calcula a data de início para o período de análise
        start_date = (datetime.datetime.now() - datetime.timedelta(days=TOP_SELLING_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute(f"""
            SELECT codigo_produto, SUM(quantidade_vendida) as total_vendido FROM {TABLE_PRODUTOS_VENDIDOS_LOG}
            WHERE data_verificacao >= ? AND status = 'processado'
            GROUP BY codigo_produto
            ORDER BY total_vendido DESC
            LIMIT ?
        """, (start_date, TOP_SELLING_COUNT))
        top_sellers = {row[0] for row in cursor.fetchall()}
        conn.close()
    except Exception as e:
        logger.error(f"Erro ao buscar produtos mais vendidos: {e}", exc_info=True)
    return top_sellers

def calculate_days_of_stock_remaining(product_code, current_stock, sales_period_days=SALES_ANALYSIS_PERIOD_DAYS):
    """
    Calcula os dias de estoque restante para um produto com base nas vendas recentes.
    Retorna os dias de estoque restante ou None se não houver dados de venda.
    """
    if current_stock is None or current_stock < 0:
        return None # Não é possível calcular com estoque inválido

    total_sold = 0
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        start_date = (datetime.datetime.now() - datetime.timedelta(days=sales_period_days)).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(f"""
            SELECT SUM(quantidade_vendida) FROM {TABLE_PRODUTOS_VENDIDOS_LOG}
            WHERE codigo_produto = ? AND data_verificacao >= ? AND status = 'processado'
        """, (product_code, start_date))
        result = cursor.fetchone()
        if result and result[0] is not None:
            total_sold = result[0]
        conn.close()

        if total_sold > 0:
            average_daily_sales = total_sold / sales_period_days
            return current_stock / average_daily_sales
    except Exception as e:
        logger.error(f"Erro ao calcular dias de estoque restante para {product_code}: {e}", exc_info=True)
    return None

def processar_entrada_unica(
    sheets,
    codigo_produto_form,
    nome_produto_form,
    qtd_prateleira,
    qtd_cabe,
    user_loja,
    user_spreadsheet_name,
    forcar_compra=False,
    alternate_sheet=None,
    forcar_planilha_alternativa=False # NOVO PARÂMETRO
):
    """
    Processa uma única entrada de dados da prateleira, calcula a necessidade
    de reposição/compra e atualiza as planilhas Google.
    """
    # Determina qual aba de reposição usar com base na loja do usuário

    logger.info(f"Iniciando processamento para: Código {codigo_produto_form}, Qtd Prateleira: {qtd_prateleira}, Cabe: {qtd_cabe}")
    
    conn_sqlite = sqlite3.connect(DATABASE_FILE)
    cursor_sqlite = conn_sqlite.cursor()

    try:
        # Buscar dados do produto (estoque_sistema, nome_produto_sistema) do banco de dados E-Trade local
        # Adicionamos marca e classe para a planilha de compras
        cursor_sqlite.execute(f"SELECT nome_produto, estoque_sistema, marca, classe FROM {TABLE_PRODUTOS_ETRADE} WHERE codigo_produto = ?", (codigo_produto_form,))
        produto_etrade = cursor_sqlite.fetchone()

        if not produto_etrade:
            msg = f"Produto '{codigo_produto_form}' não encontrado no banco de dados do sistema. Verifique o código ou execute a atualização do E-Trade."
            logger.warning(msg)
            conn_sqlite.close()
            return False, msg # Retorna apenas sucesso/falha e mensagem

        nome_produto_sistema = produto_etrade[0]
        estoque_do_sistema = int(produto_etrade[1]) if produto_etrade[1] is not None else 0
        marca_produto = produto_etrade[2] if produto_etrade[2] else "" # Pega a marca
        classe_produto = produto_etrade[3] if produto_etrade[3] else "" # Pega a classe (setor)

        logger.info(f"  Dados do E-Trade local: Nome: {nome_produto_sistema}, Estoque Sistema: {estoque_do_sistema}")

        # --- Lógica de decisão da aba de reposição ---
        # A decisão é baseada na CLASSE do produto, não na loja do usuário.
        if alternate_sheet: # Se o usuário especificou uma aba, usa ela.
            aba_reposicao_final = alternate_sheet
            aba_alternativa = ABA_REPOSICAO_LOJA2 if alternate_sheet == ABA_REPOSICAO else ABA_REPOSICAO
            logger.info(f"Aba alternativa '{alternate_sheet}' selecionada pelo usuário. Produto será adicionado em '{aba_reposicao_final}'")
        else:
            # Se forçar planilha alternativa, inverte a lógica padrão
            if forcar_planilha_alternativa:
                if classe_produto and classe_produto.upper() == 'PET':
                    aba_reposicao_final = ABA_REPOSICAO
                    aba_alternativa = ABA_REPOSICAO_LOJA2
                else:
                    aba_reposicao_final = ABA_REPOSICAO_LOJA2
                    aba_alternativa = ABA_REPOSICAO
                logger.info(f"FORÇADO: Produto da classe '{classe_produto}'. Usando ABA CONTRÁRIA: {aba_reposicao_final}, Alternativa: {aba_alternativa}")
            else:
                if classe_produto and classe_produto.upper() == 'PET':
                    aba_reposicao_final = ABA_REPOSICAO_LOJA2
                    aba_alternativa = ABA_REPOSICAO
                else:
                    aba_reposicao_final = ABA_REPOSICAO
                    aba_alternativa = ABA_REPOSICAO_LOJA2
                logger.info(f"Produto da classe '{classe_produto}'. Usando aba de reposição: {aba_reposicao_final}, Alternativa: {aba_alternativa}")

        

        # Obter planilhas pré-carregadas do dicionário 'sheets'
        sheet_reposicao = sheets.get(aba_reposicao_final)
        sheet_compras = sheets.get(ABA_COMPRAS)

        if not sheet_reposicao or not sheet_compras:
            msg = f"Erro crítico: As planilhas de trabalho necessárias ('{aba_reposicao_final}', '{ABA_COMPRAS}') não foram carregadas."
            logger.error(msg)
            conn_sqlite.close()
            return False, msg

    except Exception as e:
        msg = f"Erro ao configurar conexões (SQLite ou Google Sheets): {e}"
        logger.error(msg, exc_info=True)
        conn_sqlite.close()
        return False, msg # Retorna apenas sucesso/falha e mensagem

    novas_linhas_reposicao = []
    novas_linhas_compras = []
    data_atual_formatada = datetime.datetime.now().strftime("%d/%m/%Y") # Formato DD/MM/YYYY para data atual
    responsavel = user_spreadsheet_name or "RBAGROKA" # Usa o nome do usuário ou um fallback
    status_aberto = "ABERTO"
    
    acao_reposicao_efetivada = False
    
    # Identifica os produtos mais vendidos para a lógica proativa de compras
    top_selling_products_codes = get_top_selling_products()
    acao_compras_efetivada = False

    try:
        # Seu cálculo: estoque do sistema - a quantidade da prateleira = estoque (backstock)
        estoque_backstock = estoque_do_sistema - qtd_prateleira
        logger.info(f"  Cálculo: Estoque Sistema ({estoque_do_sistema}) - Qtd Prateleira ({qtd_prateleira}) = Backstock ({estoque_backstock})")

        # Colunas da planilha reposição: data atual, produto, codigo, quantidade para subir, responsavel (robo), status (sempre ABERTO).
        # Colunas da planilha compras: data atual, status (sempre ABERTO), setor (pego na coluna classe do db), produto, codigo, marca, quantidade total do sistema, coluna vazia, responsavel (robo)

        # Verificar se o produto já existe na planilha de reposição e seu status
        produto_ja_existe_reposicao = False
        status_existente_reposicao = ""
        try:
            # Ajuste 'in_column' se a coluna de código for diferente na sua planilha
            celula_codigo = sheet_reposicao.find(codigo_produto_form, in_column=3) # Coluna de código (índice 2 = terceira coluna)
            if celula_codigo:
                produto_ja_existe_reposicao = True
                # Ajuste o índice da coluna de status se for diferente (índice 5 = sexta coluna)
                status_existente_reposicao = sheet_reposicao.cell(celula_codigo.row, 6).value  # Ler status (sexta coluna)
                logger.info(f"Produto '{codigo_produto_form}' já existe na planilha de reposição. Status atual: '{status_existente_reposicao}'.")
        except gspread.exceptions.CellNotFound:
            logger.info(f"Produto '{codigo_produto_form}' não encontrado na planilha de reposição (nova entrada).")
        except Exception as e: # Considerar ser mais específico com exceções do gspread aqui
            logger.error(f"Erro ao verificar existência/status do produto '{codigo_produto_form}' na planilha de reposição: {e}", exc_info=True)
            return False, f"Erro ao verificar status do produto na planilha de Reposição: {e}"

        # Se o Produto já existe na planilha de REPOSIÇÃO com status ABERTO, não adiciona à REOSIÇÃO.
        if produto_ja_existe_reposicao and status_existente_reposicao == status_aberto:
            logger.info(f"Produto '{codigo_produto_form}' já está na planilha de Reposição com status 'ABERTO'. Nenhuma nova linha de reposição será adicionada.")
            # Mesmo que não adicione à reposição, a lógica de compras ainda pode ser acionada se necessário.
        else: # Produto não existe na reposição ou status não é ABERTO, então pode adicionar se a lógica de cálculo indicar
            # --- LÓGICA DE CÁLCULO DE REPOSIÇÃO CORRIGIDA ---
            quantidade_necessaria = qtd_cabe - qtd_prateleira
            quantidade_para_subir = 0

            if estoque_backstock > 0 and quantidade_necessaria > 0:
                # A quantidade a repor é o menor valor entre o que é necessário e o que há no backstock.
                quantidade_para_subir = min(estoque_backstock, quantidade_necessaria)

            if quantidade_para_subir > 0:
                novas_linhas_reposicao.append([
                    data_atual_formatada, nome_produto_sistema, codigo_produto_form,
                    quantidade_para_subir, responsavel, status_aberto
                ])
                logger.info(f"    Ação para '{codigo_produto_form}': Repor {quantidade_para_subir} unidade(s).")


        # Lógica de decisão para COMPRAS
        # Condição 1: O usuário forçou a compra manualmente (prioridade máxima).
        # Condição 2: O backstock é insuficiente (<= 0).
        # Condição 3: O produto é um dos mais vendidos (proativo).
        is_top_seller = codigo_produto_form in top_selling_products_codes
        
        sugerir_compra = False
        motivo_compra = ""

        if forcar_compra:
            sugerir_compra = True
            motivo_compra = "Manual"
        elif estoque_backstock <= 0:
            sugerir_compra = True
            motivo_compra = "Estoque Baixo"
        elif is_top_seller and estoque_do_sistema > 0:
            sugerir_compra = True
            motivo_compra = "Top Vendas"

        if sugerir_compra:
            novas_linhas_compras.append([
                data_atual_formatada, status_aberto, classe_produto, nome_produto_sistema, codigo_produto_form, 
                marca_produto, estoque_do_sistema, "", responsavel
            ])
            logger.info(f"    Ação para '{codigo_produto_form}': Adicionado à compra (Motivo: {motivo_compra}).")
       
        if estoque_backstock < 0:
            msg_retorno = f"Atenção para '{codigo_produto_form}': Quantidade na prateleira ({qtd_prateleira}) é maior que o estoque do sistema ({estoque_do_sistema}). Backstock negativo ({estoque_backstock}). Verifique os dados."
            logger.warning(msg_retorno)
            conn_sqlite.close()
            return True, msg_retorno # Sucesso na execução da lógica, mas com aviso.
        
        # Salvar resultados nas planilhas Google
        if novas_linhas_reposicao:
            sheet_reposicao.append_rows(novas_linhas_reposicao, value_input_option='USER_ENTERED')
            acao_reposicao_efetivada = True
            logger.info(f"{len(novas_linhas_reposicao)} linhas adicionadas à '{aba_reposicao_final}'.")
        
        # Lógica para adicionar/atualizar na planilha de compras
        linhas_para_adicionar_compras_final = []
        for compra_prevista in novas_linhas_compras:
            codigo_compra = compra_prevista[4] 
            qtd_sistema_atual_compra = compra_prevista[6] 
            motivo_da_compra = compra_prevista[7]
            
            produto_ja_em_compras_aberto = False # Flag para indicar se já existe e está aberto
            try:
                celula_codigo_compras = sheet_compras.find(codigo_compra, in_column=5) 
                if celula_codigo_compras:
                    status_existente_compras = sheet_compras.cell(celula_codigo_compras.row, 2).value 
                    if status_existente_compras == status_aberto:
                        produto_ja_em_compras_aberto = True
                        qtd_sistema_planilha_compras_str = sheet_compras.cell(celula_codigo_compras.row, 7).value 
                        try:
                            qtd_sistema_planilha_compras = int(qtd_sistema_planilha_compras_str) if qtd_sistema_planilha_compras_str else 0
                        except ValueError:
                            qtd_sistema_planilha_compras = 0

                        if qtd_sistema_planilha_compras != qtd_sistema_atual_compra:
                            sheet_compras.update_cell(celula_codigo_compras.row, 7, qtd_sistema_atual_compra)
                        else:
                            logger.info(f"Produto '{codigo_compra}' já está na planilha de Compras com status 'ABERTO' e mesma quantidade. Nenhuma atualização necessária.")
                    # else: Se existe mas status não é ABERTO, será adicionado como nova linha.
            except gspread.exceptions.CellNotFound:
                logger.info(f"Produto '{codigo_compra}' não encontrado na planilha de compras (será nova entrada).")
            except Exception as e_compras_check:
                logger.error(f"Erro ao verificar/atualizar produto '{codigo_compra}' na planilha de compras: {e_compras_check}", exc_info=True)
            
            if not produto_ja_em_compras_aberto: 
                linhas_para_adicionar_compras_final.append(compra_prevista)

        if linhas_para_adicionar_compras_final:
            sheet_compras.append_rows(linhas_para_adicionar_compras_final, value_input_option='USER_ENTERED')
            acao_compras_efetivada = True
            logger.info(f"{len(linhas_para_adicionar_compras_final)} nova(s) linha(s) adicionada(s) à '{ABA_COMPRAS}'.")


        conn_sqlite.close()
        
        msg_final_partes = []
        if novas_linhas_reposicao:
            msg_final_partes.append(f"{len(novas_linhas_reposicao)} item(ns) para REPOSIÇÃO.")
        
        # Para a mensagem de compras, consideramos o que foi efetivamente adicionado ou se já existia
        if linhas_para_adicionar_compras_final:
            msg_final_partes.append(f"{len(linhas_para_adicionar_compras_final)} item(ns) adicionado(s) para COMPRAS.")
        elif any(compra[4] == codigo_produto_form for compra in novas_linhas_compras) and not linhas_para_adicionar_compras_final:
            # Se estava previsto para compra, mas não foi adicionado (pq já existia e qtd igual)
            msg_final_partes.append(f"Item para COMPRAS já listado e atualizado (ou sem necessidade de alteração).")


        if not msg_final_partes: # Se nenhuma ação e backstock não é negativo
            if produto_ja_existe_reposicao and status_existente_reposicao == status_aberto:
                 # A mensagem de "já existe na reposição" já foi retornada se essa foi a única condição
                 # Aqui, tratamos o caso onde não houve reposição por cálculo, nem compra efetiva.
                 return True, f"Nenhuma ação de reposição ou compra necessária para '{codigo_produto_form}' (Backstock: {estoque_backstock})."
            else: # Caso geral de nenhuma ação
                 return True, f"Nenhuma ação de reposição ou compra necessária para '{codigo_produto_form}' (Backstock: {estoque_backstock})."

        return True, f"Produto '{codigo_produto_form}': " + " ".join(msg_final_partes), aba_alternativa

    except Exception as e_proc:
        msg = f"Erro durante o processamento da lógica de decisão ou atualização do Google Sheets para o código '{codigo_produto_form}': {e_proc}"
        logger.error(msg, exc_info=True)
        if conn_sqlite: # Garante que a conexão seja fechada se ainda estiver aberta
            conn_sqlite.close()
        return False, msg

if __name__ == '__main__':
    pass
