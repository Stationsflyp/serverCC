// Este código va en tu ImGui, donde está el botón AUTHORIZATION
// Asume que tienes una instancia global de OxcyAuth y variables globales para usuario/contraseña

// En tu archivo principal (main.cpp), declara esto:
// OxcyAuth g_auth;
// 
// Y en tu función de inicialización (antes de ImGui):
// g_auth.init();

// En tu loop de ImGui:
ImGui::InputTextEx(texture::user_input, "Username",
    "Enter your name", globals.username, 65,
    ImVec2(290, 40), NULL, NULL, NULL);
ImGui::InputTextEx(texture::key_input, "Password",
    "Enter your password", globals.password, 65,
    ImVec2(290, 40), NULL, NULL, NULL);

if (ImGui::Button("AUTHORIZATION", ImVec2(290, 40))) {
    // Validar que los campos no estén vacíos
    if (std::strlen(globals.username) == 0 || std::strlen(globals.password) == 0) {
        MessageBoxA(0, "Ingresa usuario y contrasena", "Error", MB_ICONERROR);
    } else {
        // Llamar a validate_user con la instancia global persistente
        if (g_auth.validate_user(globals.username, globals.password)) {
            // El login fue exitoso, cambiar a la pantalla de dashboard
            page = 1;
            logged_in = true;
        }
    }
}
