:: Check for Python installation
python --version 2>NUL
if errorlevel 1 goto errorNoPython
echo.
echo  Installing prerequisites...
set pwd=%cd%
pip install --no-index --find-links %cd% -r requirements.txt
echo.
echo  --------------------------------
echo   Adding BIG-IP credentials to Vault. Please ensure that the user can be used to SSH and iControl.
python main.py --Update-Credentials BIG-IP
:: Todo create scheduler
echo  --------------------------------
echo   Creating scheduler for daily at 0:00...
schtasks /create /sc daily /tn "BIG-IP Scheduler\Address List Updater" /tr "python %cd%\main.py" /st 00:00
echo  --------------------------------
echo   Installation complete.
echo  --------------------------------
pause



:errorNoPython
echo Error^: Python is not installed.
exit