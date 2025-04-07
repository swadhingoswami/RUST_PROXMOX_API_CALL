Proxmox Rust Library – Documentation :

📌 1. Overview
This Rust library provides a secure, performant, and asynchronous interface to interact with the Proxmox Virtual Environment (PVE) REST API. It allows developers and DevOps teams to automate and integrate Proxmox cluster management directly within their Rust applications.

🧭 Use Cases
Authenticate and interact with Proxmox via REST API

Retrieve VM, storage, and backup details

Launch backups and monitor their status

Build DevOps tooling for Proxmox infrastructure


🔐 2. Security Features
This library is designed with security-first principles using modern Rust practices:

✅ HTTPS Encryption
Uses reqwest with native-tls to enforce TLS encryption

All traffic between client and Proxmox API is end-to-end encrypted

Prevents sensitive information (passwords, tokens) from being exposed on the network

✅ Secure Certificate Verification
TLS certificate validation is enabled by default

Verifies server identity and authenticity to prevent MITM (Man-In-The-Middle) attacks

You can use custom certificates or internal CA if using Proxmox in a private network

let client = reqwest::Client::builder()
    .https_only(true)
    .use_rustls_tls()
    .cookie_provider(jar)
    .build()?;

🔒 Recommended: Use certificates issued by a trusted CA or configure your internal CA properly on the client machine.

⚡ 3. Asynchronous & Fast
🚀 Async Powered by Tokio
All HTTP interactions are performed using async fn, providing non-blocking I/O

Scales well for concurrent API requests (e.g., querying VMs and backups in parallel)

⚙️ Performance Benchmark (Estimation)
Operation	Time (typical)
Login (with TLS)	~100–200 ms
Get VM List	~50–150 ms
Fetch Backup Info	~50–120 ms
⚠️ Actual performance depends on network latency, cluster load, and TLS handshake speed.

🧰 4. APIs Covered
Feature	HTTP Method	API Endpoint
Login	POST	/api2/json/access/ticket
Get VMs List	GET	/api2/json/nodes/{node}/qemu
Get VM Config	GET	/api2/json/nodes/{node}/qemu/{vmid}/config
Get Storage List	GET	/api2/json/nodes/{node}/storage
Get Backup Files	GET	/api2/json/nodes/{node}/storage/{storage}/content
Start Backup Job	POST	/api2/json/nodes/{node}/vzdump
Get Backup Status	GET	/api2/json/nodes/{node}/tasks/{upid}/status
Get Task History	GET	/api2/json/nodes/{node}/tasks
🏗️ 5. Architecture Highlights
Built on modular design (ProxmoxClient struct) that manages:

Auth sessions

Cookie management

CSRF token injection

Easily extendable for other API verbs: POST, PUT, DELETE

JSON parsing done using serde/serde_json

✅ 6. Sample Usage

let client = ProxmoxClient::login("https://your-proxmox-host:8006", "root@pam", "yourpassword").await?;
let vms = client.get("nodes/pve/qemu").await?;
println!("VMs: {:#?}", vms);

🧪 7. Testing & Build
🔧 Build Library

cargo build --release


cargo test

🚀 8. Planned Features
VM lifecycle support (start, stop, suspend, reboot)

Snapshot/restore APIs

Container support (LXC)

WebSocket support for task logs

Error enum with richer error context

🙌 Contributing
PRs and issues are welcome! You can help extend the SDK by implementing support for more endpoints and improving deserialization models.




