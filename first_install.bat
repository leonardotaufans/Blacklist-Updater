:: Check for Python installation
python --version 2>NUL
if errorlevel 1 goto errorNoPython
echo.
echo  Installing prerequisites...
pip install keyring numpy paramiko
echo.
echo  --------------------------------
echo   Adding NAS credentials to Vault.
python main.py --Update-Credentials NAS
echo   Adding BIG-IP credentials to Vault. Please ensure that the user can be used to SSH.
python main.py --Update-Credentials BIG-IP
:: Todo create scheduler
echo  --------------------------------
echo   Creating scheduler...
set pwd=%cd%
schtasks /create /sc daily /tn "BIG-IP Scheduler\Address List Updater" /tr "python %cd%\main.py" /st 00:00
echo  --------------------------------
echo   Installation complete.
echo  --------------------------------
pause



:errorNoPython
echo Error^: Python is not installed.
exit