# File-Controller-Management


when you compile gpg_wrapper.c
you need to run

sudo apt-get install libgpgme-dev







gcc -Wall -I./include -o factoreal src/main.c src/gpg_wrapper.c src/logger.c src/auth.c -lgpgme -lsodium


password hash
sudo apt update
sudo apt install libsodium-dev
