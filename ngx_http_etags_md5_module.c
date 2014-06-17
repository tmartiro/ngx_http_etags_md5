/*
 * Author: Tigran Martirosyan (tmartiro@frostsecurity.com)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

typedef struct {
    ngx_uint_t  etagmd5;
    ngx_uint_t	etag_md5_max_size;
} ngx_http_etags_md5_loc_conf_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_uint_t ngx_http_test_if_match(ngx_http_request_t *r, ngx_table_elt_t *header);
static char * md5sum_frost(char* file,ngx_http_request_t *r);
static void * ngx_http_etags_md5_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_etags_md5_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_etags_md5_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_etags_md5_header_filter(ngx_http_request_t *r);

static ngx_command_t  ngx_http_etags_md5_commands[] = {
    { ngx_string( "etagmd5" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_etags_md5_loc_conf_t, etagmd5 ),
      NULL },

    { ngx_string( "etag_md5_max_size" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_etags_md5_loc_conf_t, etag_md5_max_size ),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_etags_md5_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_etags_md5_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_etags_md5_create_loc_conf,  /* create location configuration */
    ngx_http_etags_md5_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t  ngx_http_etags_md5_module = {
    NGX_MODULE_V1,
    &ngx_http_etags_md5_module_ctx,  /* module context */
    ngx_http_etags_md5_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void * ngx_http_etags_md5_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_etags_md5_loc_conf_t    *conf;

    conf = ngx_pcalloc( cf->pool, sizeof( ngx_http_etags_md5_loc_conf_t ) );
    if ( NULL == conf ) {
        return NGX_CONF_ERROR;
    }
    conf->etagmd5   = NGX_CONF_UNSET_UINT;
    conf->etag_md5_max_size = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * ngx_http_etags_md5_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_etags_md5_loc_conf_t *prev = parent;
    ngx_http_etags_md5_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value( conf->etagmd5, prev->etagmd5, 0 );
    ngx_conf_merge_uint_value(conf->etag_md5_max_size, prev->etag_md5_max_size, 10);

    if ( conf->etagmd5 != 0 && conf->etagmd5 != 1 ) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "etagmd5 must be 'on' or 'off'");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_etags_md5_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_etags_md5_header_filter;

    return NGX_OK;
}


static char* md5sum_frost(char* filename, ngx_http_request_t *r){
    int n;
    MD5_CTX c;
    char buf[1024];
    ssize_t bytes;
    unsigned char out[MD5_DIGEST_LENGTH]; 
    //dzevapoxeci vor nginx-i poolic memory allokacni
    char* mydata = ngx_pnalloc(r->pool, MD5_DIGEST_LENGTH * 3);
    char* startp_mydata;

    startp_mydata = mydata;
    MD5_Init(&c);
    int fd = open(filename, O_RDONLY);
    bytes=read(fd, buf, 1024);
    while(bytes > 0)
    {
            MD5_Update(&c, buf, bytes);
            bytes=read(fd, buf, 1024);
    }

    MD5_Final(out, &c);
    close(fd);

    for(n=0; n < MD5_DIGEST_LENGTH; n++)
    {
        sprintf(mydata, "%02x", out[n] );
        mydata=mydata + 2;

    }

    return startp_mydata;
}

static ngx_int_t ngx_http_etags_md5_header_filter(ngx_http_request_t *r) {
    int          status;
    ngx_log_t   *log;
    u_char      *p;
    size_t       root;
    ngx_str_t    path;
    ngx_table_elt_t  *etag;
    struct stat  stat_result;
    ngx_http_etags_md5_loc_conf_t   *loc_conf;


    log = r->connection->log;
    
    loc_conf = ngx_http_get_module_loc_conf( r, ngx_http_etags_md5_module );
    
    // Ete aktivacraca configic
    if ( 1 == loc_conf->etagmd5 ) {
        p = ngx_http_map_uri_to_path( r, &path, &root, 0 );
        if ( NULL == p ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }


        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                        "http filename: \"%s\"", path.data);
   	//File tenum em ka te chka 
        status = stat( (char *) path.data, &stat_result );
    
        // Eta ka sharunakum em hashvarkners
        if ( 0 == status && (unsigned int)stat_result.st_size < loc_conf->etag_md5_max_size && loc_conf->etag_md5_max_size != 0 ) {
		
            	ngx_http_clear_etag(r);        
    		etag = ngx_list_push(&r->headers_out.headers);
    		if (etag == NULL) {
        		return NGX_ERROR;
    		}	

    		etag->hash = 1;
    		ngx_str_set(&etag->key, "ETag");

    		etag->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);
    		if (etag->value.data == NULL) {
        		return NGX_ERROR;
    		}

    		etag->value.len = ngx_sprintf(etag->value.data, "\"%s\"", md5sum_frost( (char*)path.data,r) ) - etag->value.data;
    		r->headers_out.etag = etag;

		//ardyoq mer md5 brnum not match headerum graci het
		if (r->headers_in.if_none_match && ngx_http_test_if_match(r, r->headers_in.if_none_match)) {
			r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
			r->headers_out.status_line.len = 0;
			r->headers_out.content_type.len = 0;
			ngx_http_clear_content_length(r);
			ngx_http_clear_accept_ranges(r);

			if (r->headers_out.content_encoding) {
				r->headers_out.content_encoding->hash = 0;
				r->headers_out.content_encoding = NULL;
			}
		}
            }
    }

    return ngx_http_next_header_filter(r);
}

static ngx_uint_t
ngx_http_test_if_match(ngx_http_request_t *r, ngx_table_elt_t *header)
{
    u_char     *start, *end, ch;
    ngx_str_t  *etag, *list;

    list = &header->value;

    if (list->len == 1 && list->data[0] == '*') {
        return 1;
    }

    if (r->headers_out.etag == NULL) {
        return 0;
    }

    etag = &r->headers_out.etag->value;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http im:\"%V\" etag:%V", list, etag);

    start = list->data;
    end = list->data + list->len;

    while (start < end) {

        if (etag->len > (size_t) (end - start)) {
            return 0;
        }

        if (ngx_strncmp(start, etag->data, etag->len) != 0) {
            goto skip;
        }

        start += etag->len;

        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t') {
                start++;
                continue;
            }

            break;
        }

        if (start == end || *start == ',') {
            return 1;
        }

    skip:

        while (start < end && *start != ',') { start++; }
        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t' || ch == ',') {
                start++;
                continue;
            }

            break;
        }
    }

    return 0;
}
