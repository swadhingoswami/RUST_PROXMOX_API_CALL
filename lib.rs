use std::collections::HashMap;
//use std::sync::{Arc, Mutex, RwLock, OnceLock};
use std::sync::{Arc, RwLock, OnceLock};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::timeout;
use url::Url;
//use reqwest::{Client, Certificate, Error as ReqwestError, Response, Method};
use reqwest::{Client, Certificate, Error as ReqwestError, Method};
use std::fs;
use std::process::Stdio;
use tokio::process::Command;
// regex::bytes::Regex;
use serde_json::Value;
use regex::Regex;
//use bytes::Bytes;
//use http_body::Body;
//use http_body_util::{BodyExt, Full};


// Static client instance
static PROXMOX_CLIENT: OnceLock<Arc<RwLock<ProxmoxClient>>> = OnceLock::new();

// Custom error enum
#[derive(Error, Debug)]
pub enum ProxmoxError {
    #[error("❌ Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("❌ HTTP Error: {0}")]
    HttpError(ReqwestError),
    #[error("❌ API Error: {0} - {1}")]
    ApiError(u16, String), // Status code, message
    #[error("❌ Authentication Error: {0}")]
    AuthenticationError(String),
    #[error("❌ Timeout Error")]
    TimeoutError,
    #[error("❌ Thread Safety Error: {0}")]
    ThreadSafetyError(String),
    #[error("❌ JSON Error: {0}")]
    JsonError(serde_json::Error),
    #[error("❌ Other Error: {0}")]
    Other(String),
    #[error("❌ Proxmox API Error: {0}")] //Added for general proxmox api error
    ProxmoxApiError(String),
}

// Result type for Proxmox operations
pub type ProxmoxResult<T> = Result<T, ProxmoxError>;

// Proxmox client structure
#[derive(Debug)]
pub struct ProxmoxClient {
    http_client: Client,
    base_url: Url,
    auth_token: RwLock<Option<String>>, // Use RwLock for thread-safe access
    csrf_token: RwLock<Option<String>>,
}

// Authentication response structure
#[derive(Deserialize, Debug)]
struct AuthResponse {
    data: AuthData,
}

#[derive(Deserialize, Debug)]
struct AuthData {
    ticket: String,
    CSRFPreventionToken: Option<String>,
}

// VM details structure (for get_vm_details)
#[derive(Serialize, Deserialize, Debug)]
pub struct VmDetails {
    pub vmid: u64,
    pub name: String,
    pub status: String,
    pub cpus: u32,
    pub maxmem: u64,
    pub maxdisk: u64,
    //pub node: String,
    #[serde(default)]
    pub node: Option<String>,
}

// Snapshot structure
#[derive(Serialize, Deserialize, Debug)]
pub struct Snapshot {
    pub name: String,
    pub vmstate: u64,
}

impl ProxmoxClient {
    /// Initializes a new Proxmox client.
    ///
    /// This function performs the following steps:
    /// 1.  Parses the Proxmox server URL.
    /// 2.  Sets up the HTTP client with certificate validation.
    /// 3.  Authenticates with the Proxmox API using the provided username and password.
    /// 4.  Obtains an API token.
    /// 5.  Stores the token in a thread-safe manner.
    ///
    /// # Parameters
    ///
    /// * `proxmox_url`: The URL of the Proxmox server (e.g., "https://10.0.0.1:8006").
    /// * `username`: The Proxmox username.
    /// * `password`: The Proxmox password.
    /// * `timeout_seconds`: Timeout for API requests in seconds.
    /// * `custom_ca_cert`: Optional path to a custom CA certificate bundle (PEM format).
    ///
    /// # Returns
    ///
    /// A `ProxmoxResult` containing the initialized `ProxmoxClient` on success, or an error if initialization fails.
    pub async fn new(
        proxmox_url: &str,
        username: &str,
        password: &str,
        timeout_seconds: u64,
        custom_ca_cert: Option<&str>,
    ) -> ProxmoxResult<Self> {
        let url = Url::parse(proxmox_url)
            .map_err(|e| ProxmoxError::InvalidUrl(e.to_string()))?;
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds));
        
        // Configure certificate validation
        if let Some(cert_path) = custom_ca_cert {
            let cert_bytes = fs::read(cert_path)
                .map_err(|e| ProxmoxError::Other(format!("Failed to read custom CA certificate file: {}", e.to_string())))?;
        
            let cert = Certificate::from_pem(&cert_bytes)
                .map_err(|e| ProxmoxError::Other(format!("Failed to parse custom CA certificate: {}", e.to_string())))?;
        
            client_builder = client_builder.add_root_certificate(cert);
        }
        //client_builder = client_builder.danger_accept_invalid_certs(true); // SWADHIN

        let http_client = client_builder
            .build()
            .map_err(|e| ProxmoxError::HttpError(e))?;
        let mut client = Self {
            http_client,
            base_url: url,
            auth_token: RwLock::new(None),
            csrf_token: RwLock::new(None), 
        };
        // Authenticate and obtain token
        client.authenticate(username, password).await?;
        Ok(client)
    }

    /// Authenticates with the Proxmox API and stores the authentication token.
    async fn authenticate(&mut self, username: &str, password: &str) -> ProxmoxResult<String> {
        let auth_url = self.base_url.join("api2/json/access/ticket")
            .map_err(|e| ProxmoxError::InvalidUrl(e.to_string()))?;
        let params = HashMap::from([
            ("username", username),
            ("password", password),
        ]);
        let response = self.http_client.post(auth_url.as_str())
            .form(&params)
            .send()
            .await
            .map_err(|e| ProxmoxError::HttpError(e))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Failed to get error message".to_string());
            return Err(ProxmoxError::AuthenticationError(format!(
                    "Authentication failed with status {}: {}",
                    status.as_u16(),
                    error_text
            )));
        }

        let auth_response: AuthResponse = response.json()
            .await
            .map_err(ProxmoxError::HttpError)?;

        let auth_ticket = auth_response.data.ticket.clone();

        let mut token_guard = self.auth_token.write()
            .map_err(|e| ProxmoxError::ThreadSafetyError(e.to_string()))?;
        
        *token_guard = Some(auth_response.data.ticket);

        let mut csrf_guard = self.csrf_token.write()
            .map_err(|e| ProxmoxError::ThreadSafetyError(e.to_string()))?;
        
        *csrf_guard = auth_response.data.CSRFPreventionToken.clone();
        //*csrf_guard = auth_response.data.csrf_prevention_token.clone();
        
        //Ok(())
        Ok(auth_ticket)
    }

    /// Helper function to make authenticated API requests.
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        params: Option<HashMap<&str, &str>>, // Changed to Option
        data: Option<&serde_json::Value>,
    ) -> ProxmoxResult<T> {

        // Build the full URL
        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| ProxmoxError::InvalidUrl(e.to_string()))?;

        // Read the authentication token
        let token_guard = self
            .auth_token
            .read()
            .map_err(|e| ProxmoxError::ThreadSafetyError(e.to_string()))?;

        let token = token_guard
            .as_ref()
            .ok_or(ProxmoxError::AuthenticationError(
                "Authentication token is missing".to_string(),
            ))?;

        // Start building the request
        let mut request_builder = self
            .http_client
            .request(method.clone(), url.as_str())
            .header("Cookie", format!("PVEAuthCookie={}", token))
            .header("Authorization", format!("PVEAPIToken={}", token));

        // For non-GET methods, add CSRFPreventionToken header (if available)
    if method != Method::GET {
        if let Ok(csrf_guard) = self.csrf_token.read() {
            if let Some(csrf_token) = csrf_guard.as_ref() {
                request_builder = request_builder.header("CSRFPreventionToken", csrf_token);
            }
        }
    }

      // Add query/form parameters or JSON payload
      if let Some(params) = params {
        request_builder = if method == Method::GET {
            request_builder.query(&params)
        } else {
            request_builder.form(&params)
        };
    }



        if let Some(data) = data {
            request_builder = request_builder.json(data);
        }
        let response = request_builder
            .send()
            .await
            .map_err(|e| ProxmoxError::HttpError(e))?;

            let status = response.status();
            if !status.is_success() {
                let error_text = response.text().await.unwrap_or_else(|_| "Failed to get error message".to_string());
                return Err(ProxmoxError::ApiError(status.as_u16(), error_text));
            }
        //let json_response: serde_json::Value = response.json().await.map_err(|e| ProxmoxError::JsonError(e))?;
    
        let json_response: serde_json::Value = response.json()
            .await
            .map_err(ProxmoxError::HttpError)?;
        
        // Check for Proxmox specific error
        if let Some(error_message) = json_response["error"].as_str() {
            return Err(ProxmoxError::ProxmoxApiError(error_message.to_string()));
        }
        let result: T = serde_json::from_value(json_response).map_err(|e| ProxmoxError::JsonError(e))?;
        Ok(result)
    }

            /// This function uses the Proxmox Backup Server (PBSA) API to create a backup.
        ///
        /// # Parameters
        ///
        /// * `vm_id`: The ID of the virtual machine to back up.
        /// * `backup_type`: The type of backup ("full" or "incremental").
        /// * `storage_id`: The ID of the PBSA storage to use.
        /// * `node`: The Proxmox node where the VM is located (optional, will be queried if not provided).
        /// * `compress`: Compression type (optional).
        /// * `remove_old`: Remove old backups (optional).
        /// * `mail_notification`: Send mail on completion (optional).
        /// * `timeout_seconds`: Timeout for the backup operation in seconds (optional, no timeout if None).
        /// * `backup_path`: Path to store the backup (optional, Proxmox default if None).  Supports local paths, network shares, and mounted directories.
        ///
        /// # Returns
        ///
        /// A `ProxmoxResult` containing the full JSON response from the Proxmox API, which includes backup file creation details and the path of the backup.
        pub async fn start_backup(
            &self,
            vm_id: u64,
            backup_type: &str, 
            storage_id: &str,
            node: Option<&str>,
            compress: Option<&str>,
            remove_old: Option<&str>,
            mail_notification: Option<&str>,
            timeout_seconds: Option<u64>,
            backup_path: Option<&str>,
            mode: Option<&str>,
        ) -> ProxmoxResult<serde_json::Value> {
        
            println!("⚙️ Preparing backup for VM ID: {}", vm_id);
            println!("➡️  Preparing backup request:");
            println!("   📍 Node: {:?}", node);
            println!("   🆔 VM ID: {}", vm_id);
            println!("   📦 Storage: {}", storage_id);
            println!("   🔧 Mode: {}", mode.unwrap_or("not set"));
            println!("   🧰 Compress: {}", compress.unwrap_or("not set"));
            println!("   🧹 Remove old backups: {}", remove_old.unwrap_or("not set"));
            println!("   ✉️ Mail notification: {}", mail_notification.unwrap_or("not set"));
            println!("   📂 Backup path: {}", backup_path.unwrap_or("not set"));
        
            let node_name = match node {
                Some(n) => n.to_string(),
                None => {
                    println!("   🔍 Node not provided, querying VM details...");
                    let vm_details = self.get_vm_details_by_id(vm_id).await?;
                    let determined_node = vm_details.node.ok_or_else(|| ProxmoxError::Other(format!(
                        "Node name could not be determined for VM {}",
                        vm_id
                    )))?;
                    println!("   ✅ Determined node: {}", determined_node);
                    determined_node
                }
            };
        
            // ✅ Use vzdump endpoint for full backups
            //let endpoint = format!("api2/json/nodes/{}/vzdump", node_name);
            let endpoint = match backup_type {
                "qemu" => format!("api2/json/nodes/{}/qemu/{}/backup", node_name, vm_id),
                "lxc" => format!("api2/json/nodes/{}/lxc/{}/backup", node_name, vm_id),
                "vzdump" => format!("api2/json/nodes/{}/vzdump", node_name),
                _ => return Err(ProxmoxError::Other("Unsupported backup type".into())),
            };
            
        
            // ✅ Prepare form parameters
            let mut params: HashMap<&str, String> = HashMap::new();
            params.insert("vmid", vm_id.to_string());
            params.insert("storage", storage_id.to_string());
        
            if let Some(mode_val) = mode {
                params.insert("mode", mode_val.to_string());
            } else {
                return Err(ProxmoxError::Other("Backup 'mode' parameter is required".to_string()));
            }
        
            if let Some(compress_val) = compress {
                params.insert("compress", compress_val.to_string());
            }
            if let Some(remove_old_val) = remove_old {
                params.insert("remove", remove_old_val.to_string());
            }
            if let Some(mail_val) = mail_notification {
                params.insert("mailnotification", mail_val.to_string());
            }
            if let Some(dump_dir) = backup_path {
                params.insert("dumpdir", dump_dir.to_string());
            }
        
            println!("   📞 Calling Proxmox API Endpoint: POST /{}", endpoint);
            println!("   📋 With parameters: {:#?}", params);
        
            if let Some(secs) = timeout_seconds {
                println!("   ⏱️ Applying specific timeout: {} seconds", secs);
            } else {
                println!("   ⏱️ Using default client timeout.");
            }
        
        
            let param_refs: HashMap<&str, &str> = params
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            let request_future = self.request(
                Method::POST,
                &endpoint,
                Some(param_refs),
                None,
            );
        
            let result = if let Some(seconds) = timeout_seconds {
                match timeout(Duration::from_secs(seconds), request_future).await {
                    Ok(Ok(value)) => Ok(value),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(ProxmoxError::TimeoutError),
                }
            } else {
                request_future.await
            };
        
            match result {
                Ok(response_value) => {
                    if let Ok(pretty_json) = serde_json::to_string_pretty(&response_value) {
                        println!("   ✅ Success! Received JSON response:\n{}", pretty_json);
                    } else {
                        println!("   ✅ Success! Received JSON response: {:?}", response_value);
                    }
                    Ok(response_value)
                }
                Err(e) => {
                    println!("   ❌ Error during backup request: {:?}", e);
                    if let ProxmoxError::ApiError(code, ref body) = e {
                        println!("   ❗ API returned status code: {}", code);
                        println!("   🧾 API response body: {}", body);
                        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(body) {
                            println!("   📄 Parsed API error response: {:#?}", json_val);
                        }
                    }
                    Err(e)
                }
            }
        }
        


    
    /// Asynchronously transfers data using rsync, optionally over SSH.
    /// 
    /// # Arguments
    /// - `source`: The source directory or file path.
    /// - `destination`: The target directory or file path.
    /// - `ssh_user`: Optional SSH username.
    /// - `ssh_host`: Optional SSH host IP or DNS.
    /// - `encrypt_with_openssl`: Placeholder flag for future OpenSSL support.
    /// - `timeout_secs`: Optional timeout in seconds.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err(String)` with error details otherwise.
    pub async fn transfer_rsync(
        source: &str,
        destination: &str,
        ssh_user: Option<String>,
        ssh_host: Option<String>,
        encrypt_with_openssl: bool,
        timeout_secs: Option<u64>,
    ) -> Result<(), String> {
        let mut cmd = Command::new("rsync");
    
        cmd.args(&[
            "-avz",             // archive, verbose, compress
            "--progress",       // show progress
            "--inplace",        // write directly to destination file
            "--partial",        // resume partial transfers
            "--bwlimit=0",      // unlimited bandwidth
        ]);
    
        if encrypt_with_openssl {
            return Err("OpenSSL encryption via rsync is not implemented".into());
        }
    
        if let (Some(user), Some(host)) = (ssh_user, ssh_host) {
            let ssh_target = format!("{}@{}:{}", user, host, destination);
            cmd.arg(source).arg(ssh_target);
        } else {
            cmd.arg(source).arg(destination);
        }
    
        println!("[INFO] Executing rsync: {:?}", cmd);
    
        let future = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
    
            let status = if let Some(secs) = timeout_secs {
                timeout(Duration::from_secs(secs), future)
                    .await
                    .map_err(|_| format!("Rsync timed out after {} seconds", secs))?
                    .map_err(|e| format!("Failed to run rsync: {}", e))?
            } else {
                future.await.map_err(|e| format!("Failed to run rsync: {}", e))?
            };
    
        if !status.success() {
            return Err(format!("rsync failed with status: {}", status));
        }
    
        Ok(())
    }
    
    /// Asynchronously transfers data to cloud using rclone.
    ///
    /// # Arguments
    /// - `source`: Local source directory or file.
    /// - `remote_path`: Rclone remote destination (e.g., `s3:mybucket/backup/`).
    /// - `timeout_secs`: Optional timeout in seconds.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err(String)` with error details otherwise.
    pub async fn transfer_rclone(
        source: &str,
        remote_path: &str,
        timeout_secs: Option<u64>,
    ) -> Result<(), String> {
        let mut cmd = Command::new("rclone");
    
        cmd.args(&[
            "copy",
            source,
            remote_path,
            "--progress",
            "--transfers=4",             // parallel file transfers
            "--multi-thread-streams=4",  // per-file threads
            "--s3-chunk-size=64M",       // S3 optimization
            "--s3-upload-concurrency=4", // S3 upload threads
            "--retries=3",
            "--low-level-retries=10",
        ]);
    
        println!("[INFO] Executing rclone: {:?}", cmd);
    
        let future = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
    
            let status = if let Some(secs) = timeout_secs {
                timeout(Duration::from_secs(secs), future)
                    .await
                    .map_err(|_| format!("Rclone timed out after {} seconds", secs))?
                    .map_err(|e| format!("Failed to run rclone: {}", e))?
            } else {
                future.await.map_err(|e| format!("Failed to run rclone: {}", e))?
            };
    
        if !status.success() {
            return Err(format!("rclone failed with status: {}", status));
        }
    
        Ok(())
    }
    

    /// Retrieves details for a specific virtual machine by its ID.
    ///
    /// # Parameters
    ///
    /// * `vm_id`: The ID of the virtual machine.
    ///
    /// # Returns
    ///
    /// A `ProxmoxResult` containing the `VmDetails` structure for the specified VM.
    pub async fn get_vm_details_by_id(&self, vm_id: u64) -> ProxmoxResult<VmDetails> {
        let endpoint = format!("api2/json/nodes/{{node}}/qemu/{}", vm_id); // <-- You might need to fetch the node.

        // Make the API request.
        let json_response: serde_json::Value = self.request(Method::GET, &endpoint, None, None).await?;

        // Attempt to extract the VM details from the response.  This part is crucial
        // and depends heavily on the structure of the JSON response from the Proxmox API.
        // The following is an example of how you might extract the data, but you'll need to
        // adapt it to the actual structure of the response.  It's common for the VM details
        // to be nested within a "data" field in the response.
        let vm_details = serde_json::from_value(json_response["data"].clone())
                .map_err(|e| ProxmoxError::JsonError(e))?;

        Ok(vm_details)
    }


    /// Creates a snapshot of a virtual machine.
    ///
    /// # Parameters
    ///
    /// * `vm_id`: The ID of the virtual machine.
    /// * `snapshot_name`: The name of the snapshot to create.
    /// * `node`: The Proxmox node where the VM is located.
    /// * `description`: An optional description for the snapshot.
    pub async fn create_snapshot(
        &self,
        vm_id: u64,
        snapshot_name: &str,
        node: &str,
        description: Option<&str>,
    ) -> ProxmoxResult<()> {
        let endpoint = format!("api2/json/nodes/{}/qemu/{}/snapshot/{}", node, vm_id, snapshot_name);
        let mut params = HashMap::new();
        if let Some(desc) = description {
            params.insert("description", desc);
        }

        self.request::<serde_json::Value>(Method::POST, &endpoint, Some(params), None).await?;
        Ok(())
    }


    /// Deletes a snapshot of a virtual machine.
    ///
    /// # Parameters
    ///
    /// * `vm_id`: The ID of the virtual machine.
    /// * `snapshot_name`: The name of the snapshot to delete.
    /// * `node`: The Proxmox node where the VM is located.
    pub async fn delete_snapshot(&self, vm_id: u64, snapshot_name: &str, node: &str) -> ProxmoxResult<()> {
        let endpoint = format!("api2/json/nodes/{}/qemu/{}/snapshot/{}", node, vm_id, snapshot_name);
        self.request::<serde_json::Value>(Method::DELETE, &endpoint, None, None).await?;
        Ok(())
    }

    /// Retrieves the storage name for a given virtual machine ID.
    ///
    /// # Parameters
    ///
    /// * `vm_id`: The ID of the virtual machine.
    /// * `node`: The Proxmox node where the VM is located.
    ///
    /// # Returns
    ///
    /// A `ProxmoxResult` containing the storage name on success, or an error if the information cannot be retrieved.
   /// A `ProxmoxResult` containing the storage name on success, or an error if the information cannot be retrieved.
pub async fn get_storage_name_from_vm_id(&self, vm_id: u64, node: &str) -> ProxmoxResult<String> {
    let endpoint = format!("api2/json/nodes/{}/qemu/{}/config", node, vm_id);

    #[derive(Deserialize, Serialize, Debug)]
    struct VmConfig {
        #[serde(flatten)]
        other: serde_json::Value, // Catch all fields
    }

    // Perform the request
    let config: VmConfig = self.request(Method::GET, &endpoint, None, None).await?;

    // Debug print full config response
    eprintln!("✅ Full VM config for VM ID {}: {:#?}", vm_id, config);

    // Navigate to `data` object
    let data_obj = config
        .other
        .get("data")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            ProxmoxError::Other(format!(
                "❌ 'data' field not found or not an object in config for VM ID {}",
                vm_id
            ))
        })?;

    // Try to find the disk entry inside `data`
    for (key, value) in data_obj {
        if key.starts_with("ide") || key.starts_with("scsi") || key.starts_with("virtio") {
            if let Some(disk_str) = value.as_str() {
                // Extract storage name before colon
                let storage_name = disk_str
                    .split(':')
                    .next()
                    .ok_or_else(|| {
                        ProxmoxError::Other(format!(
                            "❌ Failed to parse storage name from disk field '{}'",
                            disk_str
                        ))
                    })?
                    .to_string();

                eprintln!("✅ Extracted storage name '{}' from key '{}'", storage_name, key);
                return Ok(storage_name);
            }
        }
    }

    Err(ProxmoxError::Other(format!(
        "❌ No disk field found in config for VM ID {} on node '{}'",
        vm_id, node
    )))
}

pub async fn get_backup_file_info(&self, node: &str, upid: &str) -> ProxmoxResult<Option<String>> {
    let endpoint = format!("api2/json/nodes/{}/tasks/{}/log", node, upid);

    #[derive(Deserialize)]
    struct LogEntry {
        n: u64,
        t: String,
    }

    #[derive(Deserialize)]
    struct TaskLog {
        data: Vec<LogEntry>,
    }

    let log: TaskLog = self.request(Method::GET, &endpoint, None, None).await?;

    for entry in log.data {
        if entry.t.contains("backup file is:") {
            if let Some(path) = entry.t.split("backup file is:").nth(1) {
                let path = path.trim().to_string();
                eprintln!("📁 Found backup file path: {}", path);
                return Ok(Some(path));
            }
        }
    }

    Ok(None) // If backup file not found
}


pub async fn get_valid_storage_id_from_vm_id(
    &self,
    vm_id: u64,
    node: &str,
) -> ProxmoxResult<String> {
    let endpoint = format!("api2/json/nodes/{}/qemu/{}/config", node, vm_id);

    #[derive(Debug, Deserialize, Serialize)]
    struct VmConfig {
        #[serde(flatten)]
        other: Value,
    }

    let config: VmConfig = self.request(Method::GET, &endpoint, None, None).await?;

    let data_obj = config
        .other
        .get("data")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            ProxmoxError::Other(format!(
                "❌ 'data' field not found or not an object in config for VM ID {}",
                vm_id
            ))
        })?;

    //let valid_storage_id = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    let valid_storage_id = Regex::new(r"^[a-zA-Z0-9_\-\.]+$").unwrap();

for (key, value) in data_obj {
    if key.starts_with("scsi") || key.starts_with("ide") || key.starts_with("virtio") {
        if let Some(disk_str) = value.as_str() {
            if let Some(storage_id) = disk_str.split(':').next() {
                if valid_storage_id.is_match(storage_id) && storage_id != "none" {
                    eprintln!("✅ Valid storage ID '{}' extracted from '{}'", storage_id, key);
                    return Ok(storage_id.to_string());
                } else {
                    eprintln!("⚠️ Skipping invalid storage ID '{}' from '{}'", storage_id, key);
                }
            }
        }
    }
}
    Err(ProxmoxError::Other(format!(
        "❌ No valid storage ID found in VM config for VM ID {} on node '{}'",
        vm_id, node
    )))
}


    pub async fn get_all_node_names(&self) -> ProxmoxResult<Vec<String>> {
        #[derive(Deserialize, Debug)]
        struct NodeInfo {
            node: String,
        }
    
        #[derive(Deserialize, Debug)]
        struct NodeList {
            data: Vec<NodeInfo>,
        }
    
        let response: NodeList = self
            .request(Method::GET, "api2/json/nodes", None, None)
            .await?;
    
        Ok(response.data.into_iter().map(|n| n.node).collect())
    }

    /// Retrieves details for all virtual machines on a Proxmox node.
    ///
    /// # Parameters
    ///
    /// * `node`: The Proxmox node to query.
    ///
    /// # Returns
    ///
    /// A `ProxmoxResult` containing a vector of `VmDetails` structures.
    pub async fn get_all_vm_details(&self, node: &str) -> ProxmoxResult<Vec<VmDetails>> {
        let endpoint = format!("api2/json/nodes/{}/qemu", node);
        #[derive(Deserialize, Serialize, Debug)] //local struct for this method
        struct VmList {
            data: Option<Vec<VmDetails>>, //Vec<VmDetails>,
        }
        let response: VmList = self.request(Method::GET, &endpoint, None, None).await?;
        //let response: VmList = self.request(Method::GET, &endpoint, None, None).await?;

        if let Some(mut vms) = response.data {
            for vm in vms.iter_mut() {
                vm.node = Some(node.to_string()); // Add node name to each VM
            }
            Ok(vms)
        } else {
            // Log and return a clear error
            eprintln!("❌ VM list is null for node: {}", node);
            Err(ProxmoxError::ApiError(
                500,
                format!("Proxmox API returned null VM list for node '{}'", node),
            ))
        }

        //let vms: VmList = self.request(Method::GET, &endpoint, None, None).await?;
        //Ok(vms.data)
    }
}

/// Initializes the global Proxmox client instance.
///
/// This function should be called once at the start of your application.
/// It uses a `OnceLock` to
/// ensure that the client is only initialized once.  Subsequent calls will return a `ThreadSafetyError`.
///
/// # Parameters
///
/// * `proxmox_url`: The URL of the Proxmox server.
/// * `username`: The Proxmox username.
/// * `password`: The Proxmox password.
/// * `timeout_seconds`: The timeout for API requests in seconds.
/// * `custom_ca_cert`: Optional path to a custom CA certificate bundle (PEM format).
pub async fn init_proxmox_client(
    proxmox_url: &str,
    username: &str,
    password: &str,
    timeout_seconds: u64,
    custom_ca_cert: Option<&str>,
) -> ProxmoxResult<()> {
    let client = ProxmoxClient::new(
        proxmox_url,
        username,
        password,
        timeout_seconds,
        custom_ca_cert,
    )
        .await?;
    PROXMOX_CLIENT.set(Arc::new(RwLock::new(client)))
        .map_err(|_| ProxmoxError::ThreadSafetyError("Proxmox client already initialized".to_string()))?;
    Ok(())
}


/// Retrieves the global Proxmox client instance.
///
/// This function returns a `Result` containing a read lock to the `ProxmoxClient`.
/// The caller is responsible
/// for releasing the lock when finished.
///
/// # Returns
///
/// A `ProxmoxResult` containing an `Arc<RwLockReadGuard<ProxmoxClient>>` on success, or an error if the client
/// has not been initialized.
/* 
pub fn get_proxmox_client() -> ProxmoxResult<Arc<RwLock<ProxmoxClient>>> {
    PROXMOX_CLIENT.get().cloned().ok_or(ProxmoxError::ThreadSafetyError("Proxmox client not initialized".to_string()))
}
*/

/// Retrieves the global Proxmox client instance.
///
/// This function returns a `Result` containing a read lock to the `ProxmoxClient`.
/// The caller is responsible for releasing the lock when finished.
///
/// # Returns
///
/// A `ProxmoxResult` containing an `Arc<RwLock<ProxmoxClient>>` on success, or an error if the client
/// has not been initialized.
pub fn get_proxmox_client() -> ProxmoxResult<Arc<RwLock<ProxmoxClient>>> {
    match PROXMOX_CLIENT.get().cloned() {
        Some(client) => {
            println!("✅ [INFO] Proxmox client retrieved successfully.");

            let read_lock = client.read().expect("Failed to acquire read lock on ProxmoxClient");

            match read_lock.auth_token.read() {
                Ok(auth_token_guard) => {
                    if let Some(token) = &*auth_token_guard {
                        println!("🔐 [DEBUG] Ticket: {}", token);
                       // println!("🔐 [DEBUG] CSRF Token: {}", csrf_token);
                    } else {
                        println!("⚠️ [DEBUG] Auth token not yet set.");
                    }
                }
                Err(e) => {
                    println!("❌ [ERROR] Failed to acquire read lock on auth_token: {:?}", e);
                }
            }

            // ✅ Drop the borrow manually
            drop(read_lock);
            Ok(client)
        }
        None => {
            println!("❌ [ERROR] Proxmox client not initialized.");
            Err(ProxmoxError::ThreadSafetyError(
                "Proxmox client not initialized".to_string(),
            ))
        }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test as tokio_test;
    //use reqwest::{Client, Error, Response, Method};
    use serde::{Deserialize, Serialize};
    //use std::collections::HashMap;
    //use url::Url;
    //use std::sync::RwLock;
    //use std::sync::Arc;
    //use std::ops::Deref;

    // Proxmox server details (These should be configurable, ideally from environment variables)
    const SERVER_URL: &str = "https://<IP>:<port>"; // Replace with your Proxmox server URL
    const USERNAME: &str = "<USER>"; // Replace with your Proxmox username
    //const USERNAME: &str = "root"; // Replace with your Proxmox username
    const PASSWORD: &str = "PASSWORD"; // Replace with your Proxmox password
    //const REALM: &str = "pam";
    const NODE_NAME: &str = "your_node_name"; // Replace with your Proxmox node name.  This is used in multiple tests.
    const TIMEOUT_SECONDS: u64 = 10; // Example timeout
    //const CUSTOM_CA_CERT: Option<&str> = None; // Or Some("/path/to/cert.pem");
    //const CUSTOM_CA_CERT: Option<&str> = Some("rajeshpve.arcserve.com");
    const CUSTOM_CA_CERT: Option<&str> = Some(r"C:\Users\Administrator\proxmox_backup_lib\src\proxmox-ca.pem");



    #[derive(Deserialize, Serialize, Debug)]
    struct Vm {
        vmid: u64,
        name: String,
        node: String,
    }



    #[tokio_test]
    async fn test_backup_and_snapshot() {
        // 1. Initialize Proxmox Client using init_proxmox_client
        init_proxmox_client(
            SERVER_URL,
            USERNAME,
            PASSWORD,
            TIMEOUT_SECONDS,
            CUSTOM_CA_CERT,
        )
        .await
        .expect("Failed to initialize Proxmox client");

        // 2. Get the Proxmox client
        let proxmox_client = get_proxmox_client().expect("Failed to get Proxmox client");

        // Get a list of VMget_all_node_names
        let node_names = proxmox_client.read().unwrap().get_all_node_names().await.unwrap();
        // 🖨️ Print all node names
        println!("📡 Available Proxmox nodes:");
        for name in &node_names {
            println!(" - {}", name);
        }
        // ✅ Choose one node (first one here, or you can choose based on a condition)
        let selected_node = node_names.first().expect("❌ No Proxmox nodes found!");
        // 🔄 Use this node name for VM detail fetching
        println!("🔍 Using node '{}' to fetch VM details", selected_node);

        // 3. Get a list of VMs
        println!("Fetching list of VMs...");
        let vms = proxmox_client.read().unwrap().get_all_vm_details(selected_node).await.unwrap();
        println!("Found {} VMs.", vms.len());

        if let Some(vm) = vms.first() {
            // Use the first VM for testing
            let vmid = vm.vmid;
            //let node = &vm.node;
            let node = vm.node.as_deref().unwrap_or("unknown");
            println!("Using VM: {} with ID: {} on Node: {}", vm.name, vmid, node);

            // 4. Get the storage name from the VM config
            println!("Getting storage name from VM config...");
            let storage_id = proxmox_client.read().unwrap().get_valid_storage_id_from_vm_id(vmid, node).await.unwrap();
            println!("Storage ID: {}", storage_id);

            // 5. Start a backup
            println!("Starting backup for VM {}...", vmid);
            
            let backup_result = proxmox_client.write().unwrap().start_backup(
                vmid,
                "vzdump", //"qemu", //"vzdump", // backup_type
                storage_id.as_str(),
                Some(node),    // Provide the node name
                Some("zstd"),    // Optional compression
                Some("1"),     // Optional: remove old backups
                Some("always"),     // Optional: mail notification setting
                Some(60),             // Optional timeout in seconds
                None,                   // Optional backup path
                Some("snapshot"),       // ✅ Required: mode "suspend", "stop", "snapshot"
            ).await;

            if let Err(err) = &backup_result {
                eprintln!("❌ Backup failed with error: {:?}", err);
            }
            assert!(backup_result.is_ok(), "Backup failed");

            //let response_str = backup_result.as_ref();

            // Print task info if successful
            println!("✅ Backup started. Task Info: {:?}", backup_result);

            

            let response_json = backup_result.expect("❌ Failed to get response JSON");

           
// Extract the "data" field (which is your UPID)

let upid = response_json
    .get("data")
    .and_then(|v| v.as_str())
    .ok_or_else(|| ProxmoxError::Other("❌ Failed to extract UPID from response".to_string()));

println!("📌 Extracted UPID: {:?}", upid);


let file_info = proxmox_client.write().unwrap().get_backup_file_info(node, upid.unwrap()).await;

println!("📌 file_info : {:?}", file_info);
        } else {
            panic!("No VMs found on node: {}", NODE_NAME); // Use the constant
        }
    }
}
