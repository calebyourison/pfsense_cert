use std::collections::HashMap;
use std::time::Duration;
use std::error::Error;
use std::fs;
use std::io::{Write};

use reqwest::blocking::{Client, Response};
use regex::Regex;
use clap::Parser;

use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "pfsense_cert")]
struct Args {
    /// Config File Path
    #[arg(long)]
    config: String,
    
    /// Certificate Output File Path
    #[arg(long)]
    cert_output: String,

    /// Key Output File Path
    #[arg(long)]
    key_output: String,

    /// Insecure Mode -- Run with caution
    #[arg(long)]
    insecure: bool,
}

#[derive(Debug, Deserialize)]
struct Config {
    pfsense: Pfsense,
    cert: Cert,
}

#[derive(Debug, Deserialize)]
struct Pfsense {
    address: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct Cert {
    id: String,
}



fn create_client(timeout: u64, insecure: bool) -> reqwest::blocking::Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .cookie_store(true);

    if insecure {
        println!("Running Insecure Mode!");
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }

    builder
        .build()
        .expect("Failed to build client")
}

struct PFSenseClient {
    url:String,
    username: String,
    password: String,
    session: reqwest::blocking::Client,    
}

impl PFSenseClient {
        
    fn get_csrf(&mut self, text: String) -> Result<String, Box<dyn Error>> {
        
        //2.8.2
        let csrf_pattern_one: Regex = Regex::new(r#"name=['"]__csrf_magic['"][^>]*value=['"]([^'"]+)['"]"#).unwrap();
        // 2.9.0
        let csrf_pattern_two: Regex = Regex::new(r#"csrfMagicToken\s*=\s*"([^"]+)""#).unwrap();

        let csrf_patterns: [Regex; 2] = [csrf_pattern_one, csrf_pattern_two];
        
        let csrf: String = csrf_patterns
            .iter()
            .find_map(|pattern| {
                pattern
                    .captures(&text)
                    .and_then(|caps| caps.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .expect("No CSRF token found");
                        
        Ok(csrf)
    }
    
    pub fn login(&mut self) -> Result<bool, Box<dyn Error>> {
        
        // Obtain csrf from login page
        let login_url = format!("{base_url}/index.php", base_url=self.url);
        let login_page_response: Response = self.session.get(&login_url).send()?;
        
        let login_csrf:String = self.get_csrf(login_page_response.text()?)?;

        
        let mut payload: HashMap<&str, &str> = HashMap::new();
        payload.insert("__csrf_magic", &login_csrf);
        payload.insert("usernamefld", &self.username);
        payload.insert("passwordfld", &self.password);
        payload.insert("login", "Sign In");
        
        let login_response:Response = self.session.post(&login_url).form(&payload).send()?;
        
        let body: String = login_response.text()?;
        
        if body.to_lowercase().contains("login") {
            println!("Login unsuccesful");
            return Ok(false)    
        }
         
        let validated_csrf: String = self.get_csrf(body)?;
        
        if validated_csrf == String::from("None") {
            println!("Unable to parse csrf token");
            return Ok(false)
        }
            
        Ok(true)
    }


    pub fn retrieve_cert(&mut self, cert_id: String) -> Result<Response, Box<dyn Error>> {
        let export_url: String = format!("{base_url}/system_certmanager.php?act=exp&id={id}", base_url = self.url, id = cert_id);
        let cert_export_response: Response = self.session.get(&export_url).send()?;

        Ok(cert_export_response)
    }

    pub fn retrieve_key(&mut self, cert_id: String) -> Result<Response, Box<dyn Error>> {
        let export_url: String = format!("{base_url}/system_certmanager.php?act=key&id={id}", base_url = self.url, id = cert_id);
        let key_export_response: Response = self.session.get(&export_url).send()?;

        Ok(key_export_response)
    }
        
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let config_file: String = args.config;
    let config_contents = fs::read_to_string(config_file)?;
    let config: Config = toml::from_str(&config_contents)?;

    let host_address:String = config.pfsense.address;
    let user: String = config.pfsense.username;
    let password: String = config.pfsense.password;
    let cert_id: String = config.cert.id;

    let cert_output = args.cert_output;
    let key_output = args.key_output;
    let insecure:bool = args.insecure;

    let mut pfsense = PFSenseClient {

        url:String::from(host_address),
        username: String::from(user),
        password:String::from(password),
        session:create_client(10, insecure),

    };

    let _ = pfsense.login();
    
    // Cert
    let cert = pfsense.retrieve_cert(cert_id.clone())?;
    let cert_bytes = cert.bytes()?;

    let mut cert_file = fs::File::create(cert_output)?;
    let _ = cert_file.write_all(&cert_bytes);

    // Key 
    let key = pfsense.retrieve_key(cert_id.clone())?;
   let key_bytes = key.bytes()?; 
    
    let mut key_file = fs::File::create(key_output)?;
    let _ = key_file.write_all(&key_bytes);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    // Account for regex patterns
    fn test_get_csrf() {

        let mut test_client = PFSenseClient {
            url:String::from(""),
            username: String::from(""),
            password:String::from(""),
            session:create_client(10, false),
        };
        
        let sid: String = String::from("sid:b7572a3e68b18d0a9e19bf30cb4449afee8435f3,1789301509");
        let csrf_text_one:String = String::from(
            "<input type=\"hidden\" name=\"__csrf_magic\" value=\"sid:b7572a3e68b18d0a9e19bf30cb4449afee8435f3,1789301509\">"
        );
        let crsf_text_two:String = String::from(
            "<script type=\"text/javascript\">if (top != self) {top.location.href = self.location.href;}</script>
            <script type=\"text/javascript\">var csrfMagicToken = \"sid:b7572a3e68b18d0a9e19bf30cb4449afee8435f3,1789301509\";var 
            csrfMagicName = \"__csrf_magic\";</script><script src=\"/csrf/csrf-magic.js\" type=\"text/javascript\"></script></head>"
        );

        let csrf_one = test_client.get_csrf(csrf_text_one).unwrap();
        println!("{}", &csrf_one);
        assert_eq!(sid, csrf_one);

        let csrf_two = test_client.get_csrf(crsf_text_two).unwrap();
        assert_eq!(sid, csrf_two);

    }
}
