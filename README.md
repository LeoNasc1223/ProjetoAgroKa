# ProjetoAgroKa — Sistema de Gestão para Agropecuária  
**Versão Demo/Portfólio (original rodou 100% em produção)**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Google Sheets API](https://img.shields.io/badge/Google_Sheets_API-34A853?style=for-the-badge&logo=google-sheets&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
![Status: Demo](https://img.shields.io/badge/Status-Vers%C3%A3o%20Demo%20de%20Produ%C3%A7%C3%A3o-orange?style=for-the-badge)

## História real do projeto
Esse sistema **foi usado todos os dias durante mais de 8 meses** em uma agropecuária real.  
Substituiu completamente planilhas manuais e automatizava:
- Controle de vendas e contas a receber
- Estoque de defensivos, fertilizantes e rações
- Relatórios diários e mensais
- Backup automático no Google Sheets

Quando saí da empresa, transformei em **versão demo para portfólio**:
- Removi todas as credenciais e dados reais
- Desativei conexões externas (Google Sheets, WhatsApp, e-mail)
- Deixei comentários detalhados explicando exatamente como funcionava em produção

Ou seja: você está vendo **código real de produção**, só limpo e comentado.

## Funcionalidades que existiam na versão original
- Automação no Computador da Agropecuária para atualizar o Banco de Dados do sistema
- Sincronização automática com Google Sheets
- Servidor que permitia ser usado em dispositivos móveis

## Como rodar a versão demo (local)
```bash
git clone https://github.com/LeoNasc1223/ProjetoAgroKa.git
cd ProjetoAgroKa
pip install -r requirements.txt
python app.py        # ou dê dois cliques em start.bat (Windows)
