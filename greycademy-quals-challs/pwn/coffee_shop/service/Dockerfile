FROM httpd:2.4
COPY ./src/ /usr/local/apache2/htdocs/
COPY ./cgi-bin/ /usr/local/apache2/cgi-bin/
RUN chmod -R 755 /usr/local/apache2/cgi-bin
COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf
RUN mkdir -p /usr/local/apache2/logs