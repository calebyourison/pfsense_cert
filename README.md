# Download Cert/Key from Pfsense
---
Very simple program to download the SSL certificate and key from a PfSense firewall.  Useful for automatic renewel if this is your local certificate authority.  

Secrets are stored in the TOML file. The certificate id can be obtained in the web browser.  This file path should be supplied to the `--config` flag.  
```toml
[pfsense]
address = "https://10.10.10.1"
# Must have "WebCfg - System: Certificate Manager" privileges
username = "some_user"
password = "some_password"

[cert]
id = "some_id"
```

Build for platform or see [releases](https://github.com/calebyourison/pfsense_cert/releases/tag/ubuntu-24.04) for Linux.

Usage:

```bash
/path/to/pfsense_cert --config "path/to/config.toml" --cert-output "/path/to/cert/test.crt" --key-output "/path/to/key/test.key" 
```

If firewall SSL certificate cannot be validated, use the `--insecure` flag.  But that seems rather odd if you're using Pfsense as your CA.

**This project is not affiliated with Pfsense.**