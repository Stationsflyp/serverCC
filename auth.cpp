#include "auth.hpp"
#include <Windows.h>
#include <curl/curl.h>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Wldap32.lib")

static std::string API_URL = "http://127.0.0.1:8000/api";

static size_t write_cb(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static std::string generate_hwid()
{
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << serial;
        return ss.str();
    }
    return "HWID_UNKNOWN";
}

static std::string get_request(const std::string& endpoint)
{
    CURL* curl = curl_easy_init();
    std::string response;
    if (!curl)
        return "";

    std::string url = "http://127.0.0.1:8000/api" + endpoint;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    return response;
}

OxcyAuth::OxcyAuth()
{
    hwid = generate_hwid();
    app_name = "OxcyShop";
    owner_id = "TODO_REPLACE_WITH_YOUR_OWNER_ID";
    secret = "TODO_REPLACE_WITH_YOUR_SECRET";
    original_owner_id = owner_id;
    original_secret = secret;
}

void OxcyAuth::init()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    if (!check_version()) {
        exit(1);
    }
    
    if (owner_id.find("TODO") != std::string::npos || secret.find("TODO") != std::string::npos) {
        MessageBoxA(0, "Perfil no configurado.\nEdita auth.cpp línea 69-70 y reemplaza los TODO con tus credenciales de la dashboard.", "OxcyAuth - Error", MB_ICONERROR);
        exit(1);
    }
    
    std::string payload =
        "{"
        "\"owner_id\":\"" + owner_id + "\","
        "\"secret\":\"" + secret + "\","
        "\"app_name\":\"" + app_name + "\""
        "}";
    
    std::string res = post("/profile/verify", payload);
    
    if (res.find("1") != std::string::npos) {
        return;
    }
    
    MessageBoxA(0, "Credenciales invalidas o servidor no disponible.", "OxcyAuth - Error", MB_ICONERROR);
    exit(1);
}

std::string OxcyAuth::post(const std::string& endpoint, const std::string& json)
{
    CURL* curl = curl_easy_init();
    std::string response;
    if (!curl)
        return "";

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, (API_URL + endpoint).c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return "";
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    
    if (http_code != 200 && http_code != 0) {
        return "";
    }
    
    return response;
}

std::string escape_json_string(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
            case '\"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (c < 32) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    return output;
}

std::string extract_json_string(const std::string& response, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = response.find(search);
    if (pos == std::string::npos) return "";
    
    pos += search.length();
    size_t end = response.find("\"", pos);
    if (end == std::string::npos) return "";
    
    return response.substr(pos, end - pos);
}

bool OxcyAuth::download_client_info(const std::string& user, const std::string& pass)
{
    if (user.empty() || pass.empty() || user.length() > 50 || pass.length() > 256) {
        return false;
    }
    
    std::string escaped_user = escape_json_string(user);
    std::string escaped_pass = escape_json_string(pass);
    
    std::string payload =
        "{"
        "\"username\":\"" + escaped_user + "\","
        "\"password\":\"" + escaped_pass + "\""
        "}";
    
    std::string res = post("/client_info", payload);
    
    if (res.empty() || res.find("\"success\":true") == std::string::npos) {
        return false;
    }
    
    std::string temp_app_name = extract_json_string(res, "app_name");
    std::string temp_owner_id = extract_json_string(res, "owner_id");
    
    if (temp_app_name.empty() || temp_owner_id.empty()) {
        return false;
    }
    
    if (temp_app_name.length() > 50 || temp_owner_id.length() > 50) {
        return false;
    }
    
    if (temp_owner_id != original_owner_id) {
        return false;
    }
    
    app_name = temp_app_name;
    owner_id = temp_owner_id;
    
    return true;
}

std::string OxcyAuth::get_app_name() const { return app_name; }
std::string OxcyAuth::get_owner_id() const { return owner_id; }
std::string OxcyAuth::get_secret() const { return secret; }

bool OxcyAuth::check_version()
{
    if (owner_id.empty() || owner_id.length() > 50) {
        MessageBoxA(0, "Configuración inválida", "OxcyAuth", MB_ICONERROR);
        return false;
    }
    
    std::string version = "1.1";
    std::string escaped_owner_id = escape_json_string(owner_id);
    std::string payload = "{\"version\":\"" + version + "\",\"owner_id\":\"" + escaped_owner_id + "\"}";
    std::string res = post("/version", payload);
    
    if (res.empty()) {
        MessageBoxA(0, "Error conectando con el servidor", "OxcyAuth", MB_ICONERROR);
        return false;
    }
    
    if (res.find("\"success\":true") == std::string::npos) {
        MessageBoxA(0, "Error al validar versión", "OxcyAuth", MB_ICONERROR);
        return false;
    }
    
    bool has_update = res.find("\"update\":true") != std::string::npos;
    if (has_update) {
        MessageBoxA(
            0,
            "Necesitas actualizar la version de tu exe, por favor contacta a tu administrador!",
            "OxcyAuth Update",
            MB_ICONERROR
        );
        return false;
    }
    
    return true;
}

void OxcyAuth::login()
{
    if (hwid.empty() || hwid.length() > 256) {
        return;
    }
    
    std::string escaped_hwid = escape_json_string(hwid);
    std::string payload = "{\"hwid\":\"" + escaped_hwid + "\"}";
    std::string res = post("/login", payload);
    
    if (res.empty()) {
        MessageBoxA(0, "No se pudo conectar al servidor", "OxcyAuth", MB_ICONWARNING);
    }
}

bool OxcyAuth::validate_user(const std::string& user, const std::string& pass)
{
    if (!download_client_info(user, pass)) {
        MessageBoxA(0, "Error descargando configuracion del cliente", "OxcyAuth", MB_ICONERROR);
        return false;
    }
    
    std::string escaped_user = escape_json_string(user);
    std::string escaped_pass = escape_json_string(pass);
    std::string escaped_hwid = escape_json_string(hwid);
    std::string escaped_owner_id = escape_json_string(owner_id);
    
    std::string payload =
        "{"
        "\"username\":\"" + escaped_user + "\","
        "\"password\":\"" + escaped_pass + "\","
        "\"hwid\":\"" + escaped_hwid + "\","
        "\"owner_id\":\"" + escaped_owner_id + "\""
        "}";
    std::string res = post("/validate", payload);
    
    bool success = res.find("\"success\":true") != std::string::npos;
    
    if (!success) {
        std::string msg = "Usuario o contrasena invalido";
        
        if (res.find("FORCE_LOGOUT") != std::string::npos) {
            MessageBoxA(0, "Tu sesion ha sido terminada por el administrador", "OxcyAuth", MB_ICONWARNING);
            exit(0);
        } else if (res.find("HWID_CHANGED") != std::string::npos) {
            msg = "Tu PC fue formateada o el hardware cambio.\n\nContacta al administrador para resetear tu HWID";
        } else if (res.find("HWID_RESET_PENDING") != std::string::npos) {
            msg = "Tu solicitud de reset HWID esta pendiente.\n\nEspera a que el administrador apruebe el reset";
        } else if (res.find("Hardware baneado") != std::string::npos) {
            msg = "Tu PC ha sido baneada";
        } else if (res.find("IP baneada") != std::string::npos) {
            msg = "Tu IP ha sido baneada";
        } else if (res.find("Usuario bloqueado") != std::string::npos) {
            msg = "Este usuario ha sido bloqueado";
        } else if (res.find("Usuario no pertenece a este perfil") != std::string::npos) {
            msg = "Este usuario no existe en tu perfil";
        } else if (res.find("Este usuario no puede acceder con el exe") != std::string::npos) {
            msg = "Este usuario solo puede acceder desde la dashboard";
        }
        
        MessageBoxA(0, msg.c_str(), "OxcyAuth", MB_ICONERROR);
    }
    
    return success;
}

void OxcyAuth::license()
{
    std::string payload = "{\"hwid\":\"" + hwid + "\"}";
    std::string res = post("/license", payload);
    
    if (res.find("\"success\":false") != std::string::npos) {
        if (res.find("Hardware baneado") != std::string::npos || 
            res.find("IP baneada") != std::string::npos) {
            MessageBoxA(0, "Tu dispositivo o IP ha sido baneado", "OxcyAuth", MB_ICONERROR);
            exit(1);
        }
    }
}

bool OxcyAuth::validate_license(const std::string& license_key)
{
    std::string payload = "{\"key\":\"" + license_key + "\",\"hwid\":\"" + hwid + "\"}";
    std::string res = post("/license", payload);
    
    if (res.find("\"success\":true") != std::string::npos || res.find("License OK") != std::string::npos) {
        return true;
    }
    
    std::string msg = "Licencia inválida";
    if (res.find("Invalid license") != std::string::npos) {
        msg = "Licencia no válida";
    } else if (res.find("Expired") != std::string::npos) {
        msg = "Licencia expirada";
    } else if (res.find("Hardware baneado") != std::string::npos) {
        msg = "Tu hardware ha sido baneado";
    } else if (res.find("HWID mismatch") != std::string::npos) {
        msg = "HWID no coincide con la licencia";
    }
    
    MessageBoxA(0, msg.c_str(), "OxcyAuth", MB_ICONERROR);
    return false;
}

bool OxcyAuth::register_with_license(const std::string& license_key, const std::string& user, const std::string& pass)
{
    std::string escaped_license = escape_json_string(license_key);
    std::string escaped_user = escape_json_string(user);
    std::string escaped_pass = escape_json_string(pass);
    std::string escaped_hwid = escape_json_string(hwid);
    
    std::string payload = 
        "{"
        "\"license_key\":\"" + escaped_license + "\","
        "\"username\":\"" + escaped_user + "\","
        "\"password\":\"" + escaped_pass + "\","
        "\"hwid\":\"" + escaped_hwid + "\""
        "}";
    
    std::string res = post("/register_with_license", payload);
    
    if (res.find("\"success\":true") != std::string::npos) {
        size_t owner_pos = res.find("\"owner_id\":\"");
        size_t secret_pos = res.find("\"secret\":\"");
        
        if (owner_pos != std::string::npos && secret_pos != std::string::npos) {
            owner_pos += 12;
            size_t owner_end = res.find("\"", owner_pos);
            owner_id = res.substr(owner_pos, owner_end - owner_pos);
            
            secret_pos += 10;
            size_t secret_end = res.find("\"", secret_pos);
            secret = res.substr(secret_pos, secret_end - secret_pos);
            
            original_owner_id = owner_id;
            original_secret = secret;
            
            return true;
        }
    }
    
    std::string msg = "Error al registrar";
    if (res.find("Usuario inválido") != std::string::npos) {
        msg = "Usuario inválido";
    } else if (res.find("Contraseña débil") != std::string::npos) {
        msg = "Contraseña débil (mínimo 8 caracteres)";
    } else if (res.find("Licencia inválida") != std::string::npos) {
        msg = "Licencia inválida";
    } else if (res.find("Licencia expirada") != std::string::npos) {
        msg = "Licencia expirada";
    } else if (res.find("HWID de licencia no coincide") != std::string::npos) {
        msg = "HWID no coincide con la licencia";
    } else if (res.find("Usuario ya existe") != std::string::npos) {
        msg = "Este usuario ya existe";
    }
    
    MessageBoxA(0, msg.c_str(), "OxcyAuth", MB_ICONERROR);
    return false;
}
