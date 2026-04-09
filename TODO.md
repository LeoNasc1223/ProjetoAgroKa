# TODO: Versão bilíngue PT/EN

## Objetivo
Implementar suporte a português e inglês no sistema, com opção de troca de idioma na interface e comentários de código em ambos os idiomas.

## Plano diário
- [ ] Dia 1: Criar infraestrutura de tradução
  - Criar `translations.py` ou arquivo de strings traduzíveis
  - Adicionar helper de tradução em `app.py`
  - Criar rota/handler para trocar idioma em `session['lang']`
  - Commit: `feat: add language infrastructure and translation helper`

- [ ] Dia 2: Adicionar seletor de idioma na interface
  - Modificar `templates/base.html` para incluir botão ou dropdown de idioma
  - Salvar preferência do usuário em sessão/cookie
  - Commit: `feat: add language selector in navbar`

- [ ] Dia 3: Traduzir base e navegação
  - Traduzir menu principal e links do `base.html`
  - Traduzir textos do rodapé, notificações e mensagens gerais
  - Commit: `feat: translate base layout and navigation`

- [ ] Dia 4: Traduzir login e mensagens do usuário
  - Traduzir `templates/login.html` e `templates/register.html`
  - Traduzir mensagens de validação e `flash()` em `app.py`
  - Commit: `feat: translate auth pages and flash messages`

- [ ] Dia 5: Traduzir páginas principais do sistema
  - Traduzir dashboards, detalhes de produto, relatórios e pesquisa global
  - Extrair todas as strings fixas para o arquivo de tradução
  - Commit: `feat: translate main pages content`

- [ ] Dia 6: Traduzir botões, labels, formulários e JS
  - Atualizar textos de botões, labels, tabelas e tooltips
  - Verificar `static/js` e traduzir strings estáticas visíveis
  - Commit: `feat: translate buttons, labels and UI text`

- [ ] Dia 7: Comentários bilíngues no código
  - Adicionar comentários em PT e EN nos arquivos principais (`app.py`, `main_logic.py`, `utils.py`, `config.py`)
  - Commit: `docs: add bilingual comments to code`

- [ ] Dia 8: Documentação e revisão final
  - Atualizar `README.md` com instruções em PT e EN
  - Testar troca de idioma e corrigir pequenos detalhes
  - Commit: `docs: update README and polish language support`