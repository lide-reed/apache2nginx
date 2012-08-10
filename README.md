#apache2nginx

A command line tool, which can be used to generate nginx config file according to given config files of Apache.

## Overview

NGINX (“engine x”) is a high performance web server, caching proxy and a Layer 7 load balancing solution. Millions of web sites on the Internet benefit from using NGINX because of its extreme performance, scalability, reliability, flexibility and security. 

However, like Apache, the configuration of NGINX is not an easy thing for most of the people. In particularly, it will take our more efforts to learn the modules and directives in Apache and Nginx when we need to migrate to NGINX from Apache server.

According to the above requirement, we developed the apache2nginx tool. The goal of this tool is generating Nginx configuration file(s) according to those of Apache. 

## Installation

Step 1: Change to your directory, for example, /opt

```bash
$ cd /opt
```

Step 2: Download and unzip source code to the above directory.

```bash
$ wget https://github.com/nhnc-nginx/apache2nginx/zipball/master
$ unzip nhnc-nginx-apache2nginx.zip
```

Step 3: Configure: you could change the PREFIX by --prefix option for the installation directory

```bash
$ cd nhnc-nginx-apache2nginx
$ ./configure --prefix=/usr/local/apache2nginx
```

Step 4: Compile:

```bash
$ make
```

Step 5: Install:

```bash
$ make install
```

Step6: Add apache2nginx to PATH environment variable.
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



