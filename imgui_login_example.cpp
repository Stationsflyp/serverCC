#include "auth.hpp"
#include <imgui.h>
#include <cstring>

OxcyAuth g_auth;
char g_username[65] = {};
char g_password[65] = {};
bool g_logged_in = false;

void render_login_ui()
{
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("OxcyShop Login", nullptr, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize)) {
        ImGui::Text("Username");
        ImGui::InputText("##username", g_username, sizeof(g_username));
        
        ImGui::Text("Password");
        ImGui::InputText("##password", g_password, sizeof(g_password), ImGuiInputTextFlags_Password);
        
        if (ImGui::Button("AUTHORIZATION", ImVec2(-1, 40))) {
            if (std::strlen(g_username) > 0 && std::strlen(g_password) > 0) {
                if (g_auth.validate_user(g_username, g_password)) {
                    g_logged_in = true;
                    std::memset(g_password, 0, sizeof(g_password));
                }
            } else {
                MessageBoxA(0, "Ingresa usuario y contrasena", "Error", MB_ICONERROR);
            }
        }
        
        ImGui::End();
    }
}

void render_dashboard_ui()
{
    if (ImGui::Begin("Dashboard", nullptr, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize)) {
        ImGui::Text("Bienvenido: %s", g_username);
        
        if (ImGui::Button("Logout", ImVec2(-1, 40))) {
            g_logged_in = false;
            std::memset(g_username, 0, sizeof(g_username));
        }
        
        ImGui::End();
    }
}

void render()
{
    if (!g_logged_in) {
        render_login_ui();
    } else {
        render_dashboard_ui();
    }
}

int main()
{
    g_auth.init();
    g_auth.check_version();
    g_auth.login();
    g_auth.license();
    
    while (true) {
        render();
    }
    
    return 0;
}
