FROM httpd:2.4
RUN sed -i '1c#!/usr/bin/perl' /usr/local/apache2/cgi-bin/printenv
COPY ./vuln /usr/local/apache2/cgi-bin/
RUN sed -i \
		-e 's/^\s*#\(LoadModule .*mod_cgid.so\)/\1/' \
		-e 's/^\s*#\(LoadModule .*mod_cgi.so\)/\1/' \
		conf/httpd.conf
RUN chmod +x /usr/local/apache2/cgi-bin/printenv
RUN echo "ServerName localhost" >> conf/httpd.conf
CMD httpd-foreground

