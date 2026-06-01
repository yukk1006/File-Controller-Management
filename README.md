# File-Controller-Management

gpg control
sudo apt-get install libgpgme-dev

password hash
sudo apt update
sudo apt install libsodium-dev

compile and settings
gcc -Wall -I./include -o factoreal src/main.c src/gpg_wrapper.c src/logger.c src/auth.c src/path_guard.c -lgpgme -lsodium
sudo chown root:root factoreal
sudo chmod 47xx factoreal
