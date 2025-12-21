#include "auth.hpp"
#include <iostream>
#include <cstring>

OxcyAuth g_auth;

// ============================================
// ESTRUCTURA DE LOGIN CON ImGui
// ============================================
/*
void RenderLoginPage() {
    ImGui::InputTextEx(texture::user_input, "Username",
        "Enter your name", globals.username, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    ImGui::InputTextEx(texture::key_input, "Password",
        "Enter your password", globals.password, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    ImGui::InputTextEx(texture::key_input, "License",
        "Enter license key", globals.key, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    
    if (ImGui::Button("AUTHORIZATION", ImVec2(290, 40))) {
        if (std::strlen(globals.username) == 0 ||
            std::strlen(globals.password) == 0 ||
            std::strlen(globals.key) == 0) {
            // Mostrar error: campos vacíos
        }
        else {
            OxcyAuth auth;
            bool valid = auth.register_with_license(globals.key, globals.username, globals.password);
            if (valid) {
                page = 2; // Cambiar página si es correcto
                memset(globals.username, 0, sizeof(globals.username));
                memset(globals.password, 0, sizeof(globals.password));
                memset(globals.key, 0, sizeof(globals.key));
            }
            else {
                // Mostrar error de autenticación
            }
        }
    }
}
*/

// ============================================
// ESTRUCTURA DE REGISTRO (REGISTER) CON ImGui
// ============================================
/*
void RenderRegisterPage() {
    ImGui::InputTextEx(texture::user_input, "Username",
        "Choose a username", globals.reg_username, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    ImGui::InputTextEx(texture::key_input, "Password",
        "Create password", globals.reg_password, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    ImGui::InputTextEx(texture::key_input, "Confirm Password",
        "Confirm password", globals.reg_password_confirm, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    ImGui::InputTextEx(texture::key_input, "License",
        "Enter license key", globals.reg_license, 65,
        ImVec2(290, 40), NULL, NULL, NULL);
    
    if (ImGui::Button("CREATE ACCOUNT", ImVec2(290, 40))) {
        if (std::strlen(globals.reg_username) == 0 ||
            std::strlen(globals.reg_password) == 0 ||
            std::strlen(globals.reg_password_confirm) == 0 ||
            std::strlen(globals.reg_license) == 0) {
            // Error: campos vacíos
        }
        else if (std::strcmp(globals.reg_password, globals.reg_password_confirm) != 0) {
            // Error: contraseñas no coinciden
        }
        else {
            OxcyAuth auth;
            bool registered = auth.register_with_license(
                globals.reg_license, 
                globals.reg_username, 
                globals.reg_password
            );
            if (registered) {
                page = 1; // Ir a login después del registro exitoso
                memset(globals.reg_username, 0, sizeof(globals.reg_username));
                memset(globals.reg_password, 0, sizeof(globals.reg_password));
                memset(globals.reg_password_confirm, 0, sizeof(globals.reg_password_confirm));
                memset(globals.reg_license, 0, sizeof(globals.reg_license));
            }
            else {
                // Error: no se pudo registrar (usuario existente, licencia inválida, etc)
            }
        }
    }
    
    ImGui::SameLine();
    if (ImGui::Button("BACK TO LOGIN", ImVec2(290, 40))) {
        page = 1;
    }
}
*/

int main()
{
    g_auth.init();
    
    if (!g_auth.check_version()) {
        return 1;
    }
    
    g_auth.login();
    g_auth.license();
    
    std::cout << "Sistema inicializado correctamente\n";
    
    return 0;
}
