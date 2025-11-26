# TODO: Transformar site em demonstração não funcional

## Objetivo
Transformar o site em uma demonstração para GitHub, onde botões que executariam ações externas abrem caixas de diálogo explicando detalhadamente o que a ação faria. Para elementos não funcionais, adicionar ícones de interrogação que explicam o que aconteceria.

## Arquivos a modificar
- [ ] Modificar templates/base.html: Adicionar modal genérico para explicações
- [ ] Modificar templates/index.html: Adicionar ícones ? ao lado de checkboxes, interceptar submit do formulário
- [ ] Modificar static/css/style.css: Adicionar estilos para ícones de interrogação
- [ ] Testar a demonstração em index.html
- [ ] Aplicar mudanças similares a outras páginas se necessário (review_sales.html, product_detail.html, etc.)

## Detalhes das explicações
- Botão "Registrar Entrada": Explicar leitura de campos, verificação no banco, cálculo de backstock, atualização de planilhas, etc.
- Checkbox "Sugerir compra mesmo com estoque no depósito": Explicar que marcaria produto na planilha de compras mesmo com estoque
- Checkbox "Marcar produto na planilha contrária": Explicar inversão PET/Loja
- Botão "Ler Código de Barras": Manter scanner ou mostrar explicação demo
