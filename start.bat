@echo off
chcp 65001 > nul

echo.
echo =================================================
echo      Iniciando o Sistema AgroKa
echo =================================================
echo.

REM Obtem o diretorio onde o script esta localizado
set "SCRIPT_DIR=%~dp0"

echo Acessando o diretorio do projeto: %SCRIPT_DIR%
REM Muda o diretorio atual para o diretorio do script
cd /d "%SCRIPT_DIR%"

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERRO: Nao foi possivel acessar o diretorio do projeto.
    echo Verifique se o script esta na pasta correta.
    echo.
    pause
    exit /b
)

echo.
echo Verificando a versao do Python...
python --version
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERRO: O comando 'python' nao foi encontrado.
    echo Verifique se o Python esta instalado e adicionado ao PATH do sistema.
    echo.
    pause
    exit /b
)

echo.
echo Iniciando a aplicacao AgroKa System (app.py)...
echo Por favor, aguarde o servidor iniciar.
echo.

python app.py

echo.
echo =================================================
echo A aplicacao foi encerrada ou houve um erro.
echo =================================================
echo.
pause