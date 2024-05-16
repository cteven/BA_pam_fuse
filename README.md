Requirements:
- gcc 
- git
- pkg-config
- libsodium


Steps:
  - libsodium installieren, wie es auf der Webseite vorgegeben ist 
    - https://doc.libsodium.org/installation
      - ./configure
      - make && make check
      - sudo make install
      - sudo ldconfig

  - Argon2 installieren
    - https://github.com/P-H-C/phc-winner-argon2?tab=readme-ov-file#usage
      - make
      - sudo make install PREFIX=/usr 
      - make test