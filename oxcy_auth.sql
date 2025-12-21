CREATE DATABASE oxcy_auth;
USE oxcy_auth;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(64),
    hwid VARCHAR(255),
    last_login DATETIME
);

CREATE TABLE licenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    license_key VARCHAR(64) UNIQUE,
    hwid VARCHAR(255),
    expires DATETIME
);
