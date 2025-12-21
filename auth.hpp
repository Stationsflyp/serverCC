#pragma once
#include <string>

class OxcyAuth
{
public:
    OxcyAuth();
    void init();
    bool check_version();
    void login();
    void license();
    bool validate_user(const std::string& user, const std::string& pass);
    bool download_client_info(const std::string& user, const std::string& pass);
    bool validate_license(const std::string& license_key);
    bool register_with_license(const std::string& license_key, const std::string& user, const std::string& pass);
    
    std::string get_app_name() const;
    std::string get_owner_id() const;
    std::string get_secret() const;
    
private:
    std::string hwid;
    std::string app_name;
    std::string owner_id;
    std::string secret;
    std::string original_owner_id;
    std::string original_secret;
    std::string post(const std::string& endpoint, const std::string& json);
};
