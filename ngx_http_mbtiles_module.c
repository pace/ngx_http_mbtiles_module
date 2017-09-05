/**
 * @file   ngx_http_mbtiles_module.c
 * @author Philip Blatter <philip@pace.car>
 * @date   Fri Sep 03 08:08:12 2017
 *
 * @brief  This modules serves map tiles from mbtiles container files
 *
 * @section LICENSE
 *
 * Copyright (c) 2017 PACE Telematics GmbH
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sqlite3.h>

typedef struct {
    ngx_http_complex_value_t *mbtiles_file;
    ngx_http_complex_value_t *mbtiles_zoom;
    ngx_http_complex_value_t *mbtiles_column;
    ngx_http_complex_value_t *mbtiles_row;
} ngx_http_mbtiles_loc_conf_t;

//static char *ngx_http_mbtiles(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_str_t_to_char_ptr(ngx_str_t str);
static char *ngx_http_mbtiles_enable(ngx_conf_t *cf, void *cmd, void *conf);
static ngx_int_t ngx_http_mbtiles_handler(ngx_http_request_t *r);

static ngx_conf_post_handler_pt ngx_http_mbtiles_enable_p = ngx_http_mbtiles_enable;

/**
 * This module let you read map tiles directly from a mbtiles file
 * and serve them as requested.
 */
static ngx_command_t ngx_http_mbtiles_commands[] = {
    { 
      ngx_string("mbtiles_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mbtiles_loc_conf_t, mbtiles_file), 
      NULL,  // this is not called for complex values?! -> &ngx_http_mbtiles_enable_p
    },
    { 
      ngx_string("mbtiles_zoom"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mbtiles_loc_conf_t, mbtiles_zoom), 
      NULL
    },
    { 
      ngx_string("mbtiles_column"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mbtiles_loc_conf_t, mbtiles_column), 
      NULL
    },
    { 
      ngx_string("mbtiles_row"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mbtiles_loc_conf_t, mbtiles_row), 
      NULL
    },

    ngx_null_command
}; /* ngx_http_mbtiles_commands */

/**
 * Create local configuration
 *
 * @param r
 *   Pointer to the request structure.
 * @return
 *   Pointer to the configuration structure.
 */
static void *
ngx_http_mbtiles_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mbtiles_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mbtiles_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
} /* ngx_http_mbtiles_create_loc_conf */

/**
 * Merge configurations
 *
 * @param r
 *   Pointer to the request structure.
 * @return
 *   Status
 */
static char *
ngx_http_mbtiles_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mbtiles_loc_conf_t *prev = parent;
    ngx_http_mbtiles_loc_conf_t *conf = child;

    if (conf->mbtiles_file == NULL) {
        conf->mbtiles_file = prev->mbtiles_file;
    }
    if (conf->mbtiles_zoom == NULL) {
        conf->mbtiles_zoom = prev->mbtiles_zoom;
    }
    if (conf->mbtiles_column == NULL) {
        conf->mbtiles_column = prev->mbtiles_column;
    }
    if (conf->mbtiles_row == NULL) {
        conf->mbtiles_row = prev->mbtiles_row;
    }

    // Workaround because ngx_conf_post_handler is not called by 
    // config engine on complex types
    if (conf->mbtiles_file != NULL) {
        return ngx_http_mbtiles_enable(cf, NULL, NULL);
    }

    return NGX_CONF_OK;
} /* ngx_http_mbtiles_merge_loc_conf */

/* The module context. */
static ngx_http_module_t ngx_http_mbtiles_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_mbtiles_create_loc_conf, /* create location configuration */
    ngx_http_mbtiles_merge_loc_conf /* merge location configuration */
}; /* ngx_http_mbtiles_module_ctx */

/* Module definition. */
ngx_module_t ngx_http_mbtiles_module = {
    NGX_MODULE_V1,
    &ngx_http_mbtiles_module_ctx, /* module context */
    ngx_http_mbtiles_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
}; /* ngx_http_mbtiles_module */

/**
 * Content handler.
 *
 * @param r
 *   Request structure pointer
 * @return
 *   Response status
 */
static ngx_int_t
ngx_http_mbtiles_handler(ngx_http_request_t *r)
{
    ngx_buf_t     *b;
    ngx_chain_t   out;
    ngx_str_t     mbtiles_file;
    ngx_str_t     mbtiles_zoom;
    ngx_str_t     mbtiles_column;
    ngx_str_t     mbtiles_row;
    sqlite3_stmt  *sqlite_stmt;
    sqlite3       *sqlite_handle;
    unsigned int  sqlite3_ret;
    unsigned char *tile_content;
    unsigned int  tile_read_bytes;

    ngx_http_mbtiles_loc_conf_t *mbtiles_config;
    mbtiles_config = ngx_http_get_module_loc_conf(r, ngx_http_mbtiles_module);

    /* let's try to get our config vars from nginx configuration */
    if (ngx_http_complex_value(r, mbtiles_config->mbtiles_file, &mbtiles_file) != NGX_OK
            || ngx_http_complex_value(r, mbtiles_config->mbtiles_zoom, &mbtiles_zoom) != NGX_OK
            || ngx_http_complex_value(r, mbtiles_config->mbtiles_column, &mbtiles_column) != NGX_OK
            || ngx_http_complex_value(r, mbtiles_config->mbtiles_row, &mbtiles_row) != NGX_OK
            ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to read mbtiles module configuration settings.");
        return NGX_ERROR;
    }

    /* we're supporting just GET and HEAD requests */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Only GET and HEAD requests are supported by the mbtiles module.");
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* get mbtiles file path with 0 termination */
    char *mbtiles_file_path;
    if (!(mbtiles_file_path = ngx_str_t_to_char_ptr(mbtiles_file))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* try to open mbtiles file */
    if (SQLITE_OK != (sqlite3_ret = sqlite3_open_v2(mbtiles_file_path, &sqlite_handle, SQLITE_OPEN_READONLY, NULL))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Opening '%s' failed", mbtiles_file_path);
        free(mbtiles_file_path);
        return NGX_HTTP_NOT_FOUND;
    }
    free(mbtiles_file_path);

    /* prepare our sql statement */
    const char* select_query = "select tile_data from tiles where zoom_level=? and tile_column=? and tile_row=?";
    const char* tail;
    if (SQLITE_OK != (sqlite3_ret = sqlite3_prepare_v2(sqlite_handle, select_query, strlen(select_query), &sqlite_stmt, &tail))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Could not prepare tile data sql statelemt");
        sqlite3_close(sqlite_handle);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* bind our values */
    if (SQLITE_OK != (sqlite3_ret = sqlite3_bind_text(sqlite_stmt, 1, (const char *) mbtiles_zoom.data, mbtiles_zoom.len, SQLITE_STATIC)
            || SQLITE_OK != sqlite3_bind_text(sqlite_stmt, 2, (const char *) mbtiles_column.data, mbtiles_column.len, SQLITE_STATIC)
            || SQLITE_OK != sqlite3_bind_text(sqlite_stmt, 3, (const char *) mbtiles_row.data, mbtiles_row.len, SQLITE_STATIC))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Could not bind values to prepared statement");
        sqlite3_close(sqlite_handle);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* execute query */
    if (SQLITE_ROW != (sqlite3_ret = sqlite3_step(sqlite_stmt))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Could not find a tile (ret=%i) for zoom=%s, column=%s, row=%s", sqlite3_ret, mbtiles_zoom.data, mbtiles_column.data, mbtiles_row.data);
        sqlite3_close(sqlite_handle);
        return NGX_HTTP_NOT_FOUND;
    }

    /* allocate buffer for the file content */
    tile_read_bytes = sqlite3_column_bytes(sqlite_stmt, 1);
    if (!(tile_content = ngx_palloc(r->pool, tile_read_bytes))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer memory.");
        sqlite3_close(sqlite_handle);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Read %i bytes for tile.", tile_read_bytes);

    /* copy the result into our internal buffer */
    ngx_memcpy(tile_content, sqlite3_column_blob(sqlite_stmt, 1), tile_read_bytes);
 
    /* close sqlite database */
    sqlite3_close(sqlite_handle);

    /* set the content-type header. */
    if (ngx_http_set_content_type(r) != NGX_OK) {
        // TODO: Read the content type from the mbtiles file and adjust mime type accordingly
        r->headers_out.content_type.len = sizeof("application/vnd.mapbox-vector-tile") - 1;
        r->headers_out.content_type.data = (u_char *) "application/vnd.mapbox-vector-tile";
    }

    /* allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = tile_content;
    b->last = tile_content + tile_read_bytes;
    b->memory = 1;
    b->last_buf = 1;

    /* sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = tile_read_bytes;
    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
} /* ngx_http_mbtiles_handler */

/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char *
ngx_http_mbtiles_enable(ngx_conf_t *cf, void *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

    /* Install the mbtiles handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mbtiles_handler;

    return NGX_CONF_OK;
} /* ngx_http_mbtiles */

/**
 * Helper to convert ngx_str_t to char *.
 *
 * @param str
 *   String as ngx_str_t struct.
 * @return string
 *   Zero terminated char *.
 */
char *
ngx_str_t_to_char_ptr(ngx_str_t str)
{
    char *ret;
    ret = malloc(str.len+1);
    if (ret == NULL) return ret;

    memset(ret, 0, str.len+1);
    strncpy(ret, (char *)str.data, str.len);

    return ret;
} /* ngx_str_t_to_char_ptr */
