# Prerequisite
## 1. Download and install Tomcat 10 on mac manually
    1. https://tomcat.apache.org/download-10.cgi 10.1.30 -> Binary -> Core -> zip
    2. SHA512 checksum comparison: shasum -a 512 apache-tomcat-10.1.30.zip
    3. unzip to home directory: tar -xf apache-tomcat-10.1.30.zip -C $HOME
    4. give execution permission to files: chmod u+x ./catalina.sh (do so with startup.sh and shutdown.sh as needed)
    5. start tomcat in background window: ./catalina.sh start
    6. NOW, http://localhost:8080 works but https://localhost:8080 doesn’t.
    7. stop tomcat: ./catalina.sh stop
    8. add <user username="gui" password="manager" roles="manager-gui"/> in conf/tomcat-users.xml to be able to manage web app from browser manually
## 2. Prepare environment variables for the program (sample below)
    1. CERTIFICATE_PATH=/absolute/path/to/certificate_file
    2. HTTP_PORT=8080
    3. KEYSTORE_PASSWORD=changeit
    4. KEYSTORE_PATH=/absolute/path/to/keystore_file
    5. SERVER_XML_PATH=/absolute/path/to/apache-tomcat-10.1.30/conf/server.xml
    6. SSL_PORT=8443
    7. TOMCAT_HOME=/absolute/path/to/apache-tomcat-10.1.30
