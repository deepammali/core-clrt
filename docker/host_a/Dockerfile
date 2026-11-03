FROM httpd:2.4.49

RUN sed -i '0,/Require all denied/s//Require all granted/' /usr/local/apache2/conf/httpd.conf

RUN mkdir -p /var/www/backup
COPY pci_prod.conf /var/www/backup/pci_prod.conf
COPY app.env /var/www/backup/app.env

EXPOSE 80
