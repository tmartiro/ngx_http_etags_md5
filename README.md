ngx_http_etags_md5
===================

module for nginx http server which replace Etag value with md5sum of the static file.

### Compilation and Installation
Download or clone this module into the directory you want.(in my case it was /usr/local/src). Then download nginx source in the same directory. At this point I tested this module for nginx version 1.6.0. So download command will be:

    curl -O http://nginx.org/download/nginx-1.6.0.tar.gz
    tar -xzf nginx-1.6.0.tar.gz
    cd nginx-1.6.0
now you need to configure the sources for compiling. To prepare the configuration for etag_md5 module against nginx source type

    configure --add-module=/usr/local/src/ngx_http_etags_md5
    make 
    make install

### Configuration
Add `etagmd5` to the relevant `location` blocks in your `nginx.conf` file:

    location / {
        ...
        etagmd5 on;
        etag_md5_max_size 512000;
        ...
    }
As you can see there is another item called `etag_md5_max_size` you need to configure. md5 checksum calculation on big files can brings poor performance effect. That is why I decided to add `etag_md5_max_size` item, where you can specify the maximum size of the file on which this module will calculate md5 hash.
