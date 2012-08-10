# Apache2Nginx

A command line tool, which can be used to generate nginx config file according to given config files of Apache.

## Overview

NGINX (“engine x”) is a high performance web server, caching proxy and a Layer 7 load balancing solution. Millions of web sites on the Internet benefit from using NGINX because of its extreme performance, scalability, reliability, flexibility and security. 

However, like Apache, the configuration of NGINX is not an easy thing for most of the people. In particularly, it will take our more efforts to learn the modules and directives in Apache and Nginx when we need to migrate to NGINX from Apache server.

According to the above requirement, we developed the apache2nginx tool. The goal of this tool is generating Nginx configuration file(s) according to those of Apache. 

## Download and Installation 

You could download source code or binary file (i386 or x86_64) to use.

### Download Binary 

```bash
$ wget https://github.com/downloads/nhnc-nginx/apache2nginx/apache2nginx-1.0.0-bin.i386.tar.bz2
$ tar jxvf apache2nginx-1.0.0-bin.i386.tar.bz2
```
Now you will get the executable file apache2nginx.

you can by follow command to try use.

```bash
$ ./apache2nginx -h
```

### Download Source Code

Step 1: Download and unzip source code to the above directory.

```bash
$ wget https://github.com/nhnc-nginx/apache2nginx/zipball/master
$ unzip nhnc-nginx-apache2nginx.zip
```

Step 2: Configure: you could change the PREFIX by --prefix option for the installation directory

```bash
$ cd nhnc-nginx-apache2nginx
$ ./configure --prefix=/usr/local/apache2nginx
```

Step 3: Compile and install

```bash
$ make && make install
```

Step 4: Add apache2nginx to PATH environment variable.
```bash
$ export PATH=/usr/local/apache2nginx/bin:$PATH
```

## Run

The easiest way to run Apache2nginx is as below:

```bash
$ apache2nginx -f /etc/httpd/conf/httpd.conf
```

Now, if it’s ok, nginx.conf will been produced.
By default, the converting result file is nginx.conf which is in the current directory.

## Docs & Help
1. Manual: [apache2nginx_manual.pdf](https://github.com/downloads/nhnc-nginx/apache2nginx/apache2nginx_manual.pdf)
2. Supported Modules [apache_module_support.pdf](https://github.com/downloads/nhnc-nginx/apache2nginx/apache_module_support.pdf)
3. Module and Directive Mapping [module_directive_mapping.pdf](http://cloud.github.com/downloads/nhnc-nginx/apache2nginx/module_directive_mapping.pdf)

## Disclaimer of Liability
THE AUTHOR(S) OF APACHE2NGINX SOFTWARE IS NOT LIABLE FOR ANY DAMAGES SUFFERED AS A RESULT OF USING, MODIFYING, CONTRIBUTING, OR COPYING THE SOFTWARE. THE AUTHOR(S) OF APACHE2NGINX SOFTWARE IS ALSO NOT LIABLE FOR ANY INDIRECT, INCIDENTAL, PUNITIVE, SPECIAL OR CONSEQUENTIAL DAMAGE (INCLUDING LOSS OF BUSINESS, REVENUE, PROFITS, USE, DATA OR OTHER ECONOMIC ADVANTAGE).

THE FUNCTION PROVIDED BY THIS TOOL CAN'T BE GUARANTEED AND ASSURED TO BE ACCURATE. THE PURPOSE OF DESIGNING THIS SOFTWARE IS TO HELP USERS EASILY CONVERTING THE APACHE CONFIGURATION FILES TO NGINX'S. USER SHOULD CHECK WHETHER THE CONVERTED RESULT IS EFFECTIVE OR NOT BEFORE USING IN THE PRODUCTION ENVIRONMENT.

THE APACHE2NGINX SOFTWARE CONVERTS THE APACHE CONFIGURATION FILES ACCORDING TO THE FUNCTION OF APACHE MODULES NOT THE DIRECTIVES. SO THERE AREN’T THE 1 TO 1 RELATIONS BETWEEN THE APACHE DIRECTIVES TO NGINX DIRECTIVES.




