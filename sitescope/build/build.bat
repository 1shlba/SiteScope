@echo off
REM ===================================================================
REM  SiteScope - Windows build script
REM
REM  Just double-click this file. It will:
REM    1. check Python is installed
REM    2. set up an isolated build environment
REM    3. produce dist\SiteScope.exe
REM    4. produce dist\SiteScope-Setup.exe, if Inno Setup is installed
REM
REM  Requirements:
REM    * Python 3.10 or newer, installed with "Add python.exe to PATH" ticked
REM    * Inno Setup 6 (optional, only needed for the installer)
REM      https://jrsoftware.org/isdl.php
REM ===================================================================

setlocal enabledelayedexpansion

REM Work from the repository root, whichever folder this was launched from.
cd /d "%~dp0\.."

REM Detect a double-click, so the window can be held open at the end.
REM When launched from Explorer, %cmdcmdline% contains this script's name;
REM when run from an existing prompt it does not.
set "DOUBLECLICKED=0"
echo %cmdcmdline% | find /i "%~nx0" >nul 2>&1 && set "DOUBLECLICKED=1"

echo.
echo  ============================================
echo    Building SiteScope for Windows
echo  ============================================
echo.

REM -- 1. Choose a Python ------------------------------------------------
REM  Deliberately pick a version rather than taking whatever happens to be
REM  first on PATH. A machine with several Pythons installed will otherwise
REM  build against a release PyInstaller may not support yet, and the failure
REM  that follows gives no hint that the wrong interpreter was used.
REM
REM  Force a specific version by passing it as an argument:  build.bat 3.12

set "PY="
set "WANTED=%~1"
call :pick_python

if not defined PY if not "%WANTED%"=="" (
    echo  [PROBLEM] Python %WANTED% was asked for but is not installed.
    echo            Installed versions:
    py -0 2>nul
    goto :fail
)

if not defined PY (
    echo  [PROBLEM] Windows cannot find Python.
    echo.
    echo   Fix it like this:
    echo     1. Go to  https://www.python.org/downloads/windows/
    echo     2. Under the latest Python 3.12 release, open the Files table and
    echo        download "Windows installer (64-bit)" - python-3.12.x-amd64.exe.
    echo        Do NOT take the source tarball or the embeddable package.
    echo     3. On the FIRST screen, tick "Add python.exe to PATH".
    echo        This is the step people miss - it is what causes this message.
    echo     4. Finish the install, then double-click this file again.
    echo.
    echo   If you installed Python from the Microsoft Store and this keeps
    echo   happening, uninstall it and use the python.org installer instead.
    goto :fail
)

for /f "tokens=2" %%v in ('!PY! --version 2^>^&1') do set "PYVER=%%v"
for /f "tokens=1,2 delims=." %%a in ("!PYVER!") do set "PYMM=%%a.%%b"
echo  [1/4] Using Python !PYVER!  ^(!PY!^)

REM A version outside the tested range may still work - say so rather than refuse.
set "TESTED=0"
for %%V in (3.10 3.11 3.12 3.13 3.14) do if "!PYMM!"=="%%V" set "TESTED=1"
if "!TESTED!"=="0" (
    echo        Note: this build is tested on Python 3.10-3.14. !PYMM! may work,
    echo        but if it fails, run:  build.bat 3.12
)

REM -- 2. Build environment ---------------------------------------------
call :drop_mismatched_venv

if not exist ".venv" (
    echo  [2/4] Creating an isolated build environment ^(first run only^)...
    !PY! -m venv .venv
    if errorlevel 1 (
        echo.
        echo  [PROBLEM] The build environment could not be created.
        echo            Try deleting the ".venv" folder and running this again.
        goto :fail
    )
) else (
    echo  [2/4] Reusing the existing build environment.
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo  [PROBLEM] The build environment could not be activated.
    goto :fail
)

echo  [3/4] Installing what the build needs ^(this can take a few minutes^)...
python -m pip install --upgrade pip --quiet --disable-pip-version-check
python -m pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo  [PROBLEM] The dependencies could not be installed.
    echo            Most likely one of these:
    echo              * no internet connection, or a firewall blocking pip
    echo              * Python !PYMM! is too new for one of the packages, so pip
    echo                tried to compile it from source and had no compiler
    echo.
    echo            For the second case, build against Python 3.12 instead:
    echo                build.bat 3.12
    goto :fail
)

python -m pip install pyinstaller --quiet --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo  [PROBLEM] PyInstaller could not be installed.
    echo            It usually does not support a brand-new Python release for
    echo            some months after that release comes out, and you are on !PYMM!.
    echo.
    echo            Build against Python 3.12 instead:
    echo                build.bat 3.12
    echo.
    echo            If 3.12 is not installed, get it from
    echo            https://www.python.org/downloads/windows/
    goto :fail
)

REM -- 3. Clean previous output -----------------------------------------
if exist "dist" rmdir /s /q "dist"
if exist "build\temp" rmdir /s /q "build\temp"

REM -- 4. Build ----------------------------------------------------------
echo  [4/4] Building SiteScope.exe - please wait...
echo.
pyinstaller build\sitescope.spec --noconfirm --clean --distpath dist --workpath build\temp --log-level WARN
if errorlevel 1 (
    echo.
    echo  [PROBLEM] The build failed. The messages above say why.
    goto :fail
)

if not exist "dist\SiteScope.exe" (
    echo.
    echo  [PROBLEM] The build finished but dist\SiteScope.exe is missing.
    goto :fail
)

REM -- 5. Check it actually starts ---------------------------------------
echo.
echo  Checking the executable runs...
dist\SiteScope.exe --version
if errorlevel 1 (
    echo.
    echo  [PROBLEM] SiteScope.exe was built but will not start.
    goto :fail
)

for %%A in ("dist\SiteScope.exe") do set /a "SIZEMB=%%~zA/1048576"
echo  Built dist\SiteScope.exe ^(about !SIZEMB! MB^)

REM -- 6. Installer, if Inno Setup is available --------------------------
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"

if defined ISCC (
    echo.
    echo  Building the installer...
    "!ISCC!" /Q "build\installer.iss"
    if errorlevel 1 (
        echo  [NOTE] The installer step failed, but SiteScope.exe is ready to use.
    ) else (
        echo  Built dist\SiteScope-Setup.exe
    )
) else (
    echo.
    echo  [SKIPPED] Inno Setup was not found, so no installer was built.
    echo            dist\SiteScope.exe runs perfectly well on its own.
    echo            Want the installer too? Install Inno Setup 6 from
    echo            https://jrsoftware.org/isdl.php and run this again.
)

REM -- Done --------------------------------------------------------------
echo.
echo  ============================================
echo    Done. Your files are in the "dist" folder.
echo  ============================================
echo.
echo   dist\SiteScope.exe          double-click to run SiteScope
if exist "dist\SiteScope-Setup.exe" echo   dist\SiteScope-Setup.exe    share this to install it properly
echo.
echo   Note: the first time you run it, Windows may show a blue
echo   "Windows protected your PC" box. That is expected for a new
echo   program that has not been code-signed. Click "More info",
echo   then "Run anyway".
echo.

if "%DOUBLECLICKED%"=="1" (
    explorer "dist"
    echo  Press any key to close this window...
    pause >nul
)
endlocal
exit /b 0

:fail
echo.
echo  ============================================
echo    Build did not complete.
echo  ============================================
echo.
if "%DOUBLECLICKED%"=="1" (
    echo  Press any key to close this window...
    pause >nul
)
endlocal
exit /b 1


REM ===================================================================
REM  Subroutines
REM
REM  These live in subroutines rather than inline blocks on purpose: cmd
REM  parses a parenthesised block in one go, so a variable set inside one is
REM  not visible later in the same block. A subroutine is parsed line by line,
REM  which keeps this logic simple and predictable.
REM ===================================================================

:pick_python
REM Sets PY to the command that runs the Python this build should use.
if not "%WANTED%"=="" (
    py -%WANTED% --version >nul 2>&1
    if not errorlevel 1 set "PY=py -%WANTED%"
    exit /b
)
REM Newest first, among the versions this build is known to work with.
for %%V in (3.14 3.13 3.12 3.11 3.10) do call :try_version %%V
REM Nothing suitable through the py launcher - fall back to plain PATH.
if defined PY exit /b
python --version >nul 2>&1
if not errorlevel 1 set "PY=python"
exit /b

:try_version
if defined PY exit /b
py -%1 --version >nul 2>&1
if not errorlevel 1 set "PY=py -%1"
exit /b

:drop_mismatched_venv
REM An environment built by a different Python cannot be reused - its installed
REM packages are for the wrong version - so remove it and let it be rebuilt.
if not exist ".venv\Scripts\python.exe" exit /b
set "VENVVER="
set "VENVMM="
for /f "tokens=2" %%v in ('.venv\Scripts\python.exe --version 2^>^&1') do set "VENVVER=%%v"
for /f "tokens=1,2 delims=." %%a in ("%VENVVER%") do set "VENVMM=%%a.%%b"
if "%VENVMM%"=="%PYMM%" exit /b
echo  [2/4] Existing environment uses Python %VENVMM% - rebuilding for %PYMM%...
rmdir /s /q ".venv"
exit /b
