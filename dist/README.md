## Signing the Executable

To sign the executable, follow these steps:

**1. Create a Self-Signed Certificate:**

Remember that self-signed certificates are not trusted by default on other machines, so this method is mainly for testing purposes. For production use, consider obtaining a certificate from a trusted CA.

Open PowerShell as Administrator.
Run the following command to create a self-signed certificate. Set CN=YourName to your own
      
```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=YourName" -CertStoreLocation "Cert:\CurrentUser\My"
```

**2. Export the Certificate to a PFX File:**
Run the following commands to export the certificate:
      
```powershell
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath "C:\path\to\cert\MyCert.pfx" -Password $password
```

**3. Sign the Executable:**
Locate `signtool.exe` in your Windows SDK installation directory, typically found in `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64`. or download from https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
Run the following command to sign the executable:

```powershell
"C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe" sign /fd SHA256 /f "C:\path\to\cert\MyCert.pfx" /p YourPassword "C:\path\to\dist\HashGen.exe"
```

    YourPassword is a placeholder for the password you set when exporting the PFX file. You should replace YourPassword with the actual password you used during the export process.


**4. Verify the Signature:**
You can verify the signature by running:

```powershell
"C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe" verify /pa "C:\path\to\dist\HashGen.exe"
```

Replace placeholders like `"YourName"`, `"YourPassword"`, and paths with the actual values you used.