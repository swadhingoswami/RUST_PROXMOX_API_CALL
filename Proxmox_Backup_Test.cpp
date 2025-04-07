#include <iostream>
#include <windows.h>
#include <string>

using namespace std;

// ✅ Server Configuration
const char* SERVER_URL = "https://<IP>:<PORT>";
const char* USERNAME = "USER";
const char* PASSWORD = "PASSWORD";
string ip = "<IP>";
unsigned short port = <PORT>;

// ✅ Function Pointer Typedefs
typedef bool (*InitClientFunc)(const char*, unsigned short);
typedef char* (*AuthenticateFunc)(const char*, const char*, const char*);
typedef char* (*GetVmDetailsFunc)(const char*, const char*);
typedef char* (*GetStorageDetailsFunc)(const char*, const char*, const char*);
typedef char* (*StartBackupFunc)(const char*, const char*, const char*, const char*);
typedef char* (*GetBackupStatusFunc)(const char*, const char*);
typedef char* (*DeleteBackupFunc)(const char*, const char*, const char*);
typedef char* (*CreateSnapshotFunc)(const char*, const char*, const char*, const char*);
typedef char* (*DeleteSnapshotFunc)(const char*, const char*, const char*, const char*);
typedef void (*FreeCStringFunc)(char*);


// ✅ Function Pointers
InitClientFunc init_proxmox_client;
AuthenticateFunc authenticate;
GetVmDetailsFunc get_vm_details;
GetStorageDetailsFunc get_storage_details;
StartBackupFunc start_backup;
GetBackupStatusFunc get_backup_status;
DeleteBackupFunc delete_backup;
CreateSnapshotFunc create_snapshot;
DeleteSnapshotFunc delete_snapshot;
FreeCStringFunc free_c_string;

// ✅ DLL Handle
HMODULE hLib = nullptr;

// ✅ Load Functions Template
template<typename T>
bool load_function(HMODULE lib, T& func, const char* name) {
    func = (T)GetProcAddress(lib, name);
    if (!func) {
        cerr << "❌ Failed to load: " << name << " (Error: " << GetLastError() << ")" << endl;
        return false;
    }
    return true;
}

// ✅ Load DLL and Functions
bool load_rust_library() {
    hLib = LoadLibraryA("proxmox_backup_lib.dll");
    if (!hLib) {
        cerr << "❌ Could not load DLL." << endl;
        return false;
    }
    cout << "✅ DLL loaded." << endl;

    bool success = true;
    success &= load_function(hLib, init_proxmox_client, "init_proxmox_client");
    success &= load_function(hLib, authenticate, "authenticate");
    success &= load_function(hLib, get_vm_details, "get_vm_details");
    success &= load_function(hLib, get_storage_details, "get_storage_name_from_vm_id");
    success &= load_function(hLib, start_backup, "start_backup");
    success &= load_function(hLib, get_backup_status, "get_backup_status");
    success &= load_function(hLib, delete_backup, "delete_backup");
    success &= load_function(hLib, create_snapshot, "create_snapshot");
    success &= load_function(hLib, delete_snapshot, "delete_snapshot");
    success &= load_function(hLib, free_c_string, "free_c_string");

    return success;
}

// ✅ Authentication Helper
string authenticate_user() {
    char* auth_token = authenticate(SERVER_URL, USERNAME, PASSWORD);
    if (!auth_token) {
        cerr << "❌ Authentication Failed!" << endl;
        return "";
    }
    string token = auth_token;
    free_c_string(auth_token);
    return token;
}

// ✅ Test 1: Get VM Details
void test_get_vm_details(const string& auth_token) {
    cout << "🔹 Testing Get VM Details..." << endl;
    char* result = get_vm_details(SERVER_URL, auth_token.c_str());
    if (result) {
        cout << "VM Details: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Failed to get VM details." << endl;
    }
}

// ✅ Test 2: Get Storage Details
void test_get_storage_details(const string& auth_token) {
    cout << "🔹 Testing Get Storage Details..." << endl;
    char* result = get_storage_details(SERVER_URL, "100", auth_token.c_str());
    if (result) {
        cout << "Storage: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Failed to get storage details." << endl;
    }
}

// ✅ Test 3: Full & Incremental Backup
void test_backup(const string& auth_token, bool full_backup) {
    cout << "🔹 Testing " << (full_backup ? "Full" : "Incremental") << " Backup..." << endl;
    char* result = start_backup(SERVER_URL, "100", full_backup ? "full" : "incremental", auth_token.c_str());
    if (result) {
        cout << "Backup Task ID: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Failed to start backup." << endl;
    }
}

// ✅ Test 4: Backup to Local Path
void test_backup_local(const string& auth_token) {
    cout << "🔹 Testing Backup to Local Path..." << endl;
    char* result = start_backup(SERVER_URL, "100", "full", "/mnt/backup");
    if (result) {
        cout << "Backup Task ID: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Backup to local path failed." << endl;
    }
}

// ✅ Test 5: Backup to Network Shared Path
void test_backup_network(const string& auth_token) {
    cout << "🔹 Testing Backup to Network Share..." << endl;
    char* result = start_backup(SERVER_URL, "100", "full", "//192.168.1.10/shared_backup");
    if (result) {
        cout << "Backup Task ID: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Backup to network share failed." << endl;
    }
}

// ✅ Test 6: Backup to Mounted Path
void test_backup_mounted(const string& auth_token) {
    cout << "🔹 Testing Backup to Mounted Path..." << endl;
    char* result = start_backup(SERVER_URL, "100", "full", "/mnt/nfs_backup");
    if (result) {
        cout << "Backup Task ID: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Backup to mounted path failed." << endl;
    }
}

// ✅ Test 7: Get Backup Status
void test_get_backup_status(const string& auth_token) {
    cout << "🔹 Testing Get Backup Status..." << endl;
    char* result = get_backup_status(SERVER_URL, "100");
    if (result) {
        cout << "Backup Status: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Failed to get backup status." << endl;
    }
}

// ✅ Test 8: Delete Backup
void test_delete_backup(const string& auth_token) {
    cout << "🔹 Testing Delete Backup..." << endl;
    char* result = delete_backup(SERVER_URL, "100", "/mnt/backup/backup-file.tar");
    if (result) {
        cout << "Delete Status: " << result << endl;
        free_c_string(result);
    } else {
        cerr << "❌ Failed to delete backup." << endl;
    }
}

// ✅ Run All Tests
int main() {
    if (!load_rust_library()) {
        return -1;
    }

    // Initialize HTTP Client (now using init_proxmox_client)
    init_proxmox_client(ip.c_str(), port);

    // Authenticate and obtain token
    string auth_token = authenticate_user();
    if (auth_token.empty()) {
        return -1;
    }

    // Run all test cases
    test_get_vm_details(auth_token);
    /*
    test_get_storage_details(auth_token);
    test_backup(auth_token, true);   // Full Backup
    test_backup(auth_token, false);  // Incremental Backup
    test_backup_local(auth_token);
    test_backup_network(auth_token);
    test_backup_mounted(auth_token);
    test_get_backup_status(auth_token);
    test_delete_backup(auth_token);*/

    cout << "✅ All tests completed!" << endl;

    // Unload DLL
    FreeLibrary(hLib);

    return 0;
}