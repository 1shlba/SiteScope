# SiteScope 
# Find out what is wrong with your website's security; but in plain English.

Sitescope is a packaged python application that can be easily installed on windows devices, that scans websites and provides vulnerability evaluation and analysis. The design is tailored towards small business and less technical users who cannot afford to employ a cybersecurity department.

How it works
Enter your website address and confirm you own it.
SiteScope visits your pages the way a browser does, and examines what comes back: certificates, security settings, cookies, forms, and files that should not be public.
You get a score out of 950 and a list of issues, most urgent first. Each one explains what it means, why it matters to your business, and how to fix it.
Export the lot as a PDF report.

It only looks. SiteScope never attacks your site, submits data or changes anything, and nothing leaves your computer.

Build it on Windows
Install Python 3.10–3.14 from python.org/downloads/windows — choose Windows installer (64-bit), and tick "Add python.exe to PATH" on the first screen.
Double-click build\build.bat.

Three to five minutes later you will have built dist\SiteScope.exe - a single file that will run on any Windows 10 or 11 machine with nothing else installed.

On first launch Windows shows a blue "Windows protected your PC" box, because the file is not code-signed. Click More info → Run anyway.

