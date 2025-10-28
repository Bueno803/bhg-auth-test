# BHG AUTH TEST

A simple authentication service built with PHP (Composer) utilizing delight-im, slim/psr7 libraries, and served by Nginx.

---

## Overview
This project provides user registration, login, and cookie-based authentication. It’s structured as a typical Composer‑based PHP app with `src/`, `public/`, and `vendor/` directories.

---

## Prerequisites
- PHP ≥ 8.1 (with `mbstring`, `openssl`, `pdo_mysql`, etc.)
- Composer ≥ 2.0
- Nginx ≥ 1.21 (or any web server that can proxy to PHP‑FPM)
- MySQL / MariaDB (or any PDO‑compatible DB)
- Git

---

## Getting Started

1. **Clone the repo**
   ```bash
   git clone https://github.com/Bueno803/bhg-auth-test.git
   ```

2. **Install dependencies**
    ```bash
    composer install
    ```

3. **Create a local environment file**
    ```bash
    cp .env.example .env
    # edit .env – set DB_HOST, DB_NAME, DB_USER, DB_PASS, JWT_SECRET, etc.
    ```

4. **Configure Nginx**
    ```Nginx
	# Default server configuration
	# Copied from /etc/nginx/sites-available/default (Ubuntu 22.04) and modified.
	# You can move that to a different file under sites-available/ and symlink that
	# to sites-enabled/ to enable it.
	server {
		listen 80;
		listen [::]:80;

		server_name ace.auth;

		root /var/www/auth-test/public;

		index index.php index.html;


		location / {
		# No fall back included here
			try_files $uri /index.php?$is_args$args;
		}

		location ~ \.php$ {
			include snippets/fastcgi-php.conf;
			fastcgi_pass unix:/run/php/php8.3-fpm.sock;
			fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
			include fastcgi_params;
		}

		# deny access to .htaccess files, if Apache's document root
		# concurs with nginx's one
		location ~ /\.ht {
			deny all;
		}
	}
    ```

8. **Reload Nginx**
    ```bash
        sudo nginx -t
        sudo systemctl reload nginx

    ```
