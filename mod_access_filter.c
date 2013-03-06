/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This filter is intended to protect a certain service from an unauthorized access.
 * Usernames send by login form (either web or client app) are checked against
 * the list of allowed user names. If a username is not present in the list, it replaced
 * with a string of zeroes, thus effectively broking any login attempt.
 */

/*
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
        ">>>>>>>>> got %s",str) ;
*/


#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#include <ctype.h>


#define MODNAME        "access_filter"
#define CONFFILE		"conf/access_filter.txt"
#define MAXLOGIN		64
#define USERFIELD		"j_username"
#define USERFIELD2		"username="

static const char s_szStkAccessName[] = "StkAccess";
module AP_MODULE_DECLARE_DATA access_filter_module;



typedef struct _LogList {
	char *login;
	struct _LogList *next;
} LogList;

typedef struct _NetList {
	char *netmask;
	LogList *names;
	struct _NetList *next;
} NetList;



typedef struct {
    int bEnabled;
	NetList *networks;
	//LogList *names;
} StkAccessConfig;

typedef struct
{
    apr_bucket_brigade *pbbTmp;
} StkAccessContext;


static void chomp(const char *s) {
	char *p;
	while (NULL != s && NULL != (p = strrchr(s, '\n')))	*p = '\0';
	while (NULL != s && NULL != (p = strrchr(s, '\r')))	*p = '\0';
} /* chomp */

static char *bucket_read_str(apr_bucket *b) {
	if (!(APR_BUCKET_IS_METADATA(b))) {
		const char *buf;
		apr_size_t nbytes;
		char *obuf;
		if (apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
			if (nbytes) {
				obuf = (char *)malloc(nbytes+1);    /* use pool? */
				memcpy(obuf, buf, nbytes);
				obuf[nbytes] = '\0';
				return obuf;				
			}
		}
	}
	return NULL;
}

static void StkAccessLoadList(apr_pool_t *p, server_rec *s, char *list_file, NetList *net) {
	int result = 0;
	char Buf[MAXLOGIN];
	apr_file_t *f = NULL;
	LogList *curr, *newlog;
	const char *fname = ap_server_root_relative(p, list_file);

	if (!fname) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                     MODNAME ": Invalid config file path %s", fname);
        return;
    }
    if ((result = apr_file_open(&f, fname, APR_READ | APR_BUFFERED,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                     MODNAME ": can't read magic file %s", fname);
        return;
    }

	net->names = NULL;
	curr = NULL;
	
	while (apr_file_gets(Buf, MAXLOGIN, f) == APR_SUCCESS) {
		chomp(Buf);
		newlog = (LogList *)apr_pcalloc(p, sizeof *curr);
		newlog->login = (char*)apr_pcalloc(p, strlen(Buf)+1);
		strcpy(newlog->login,Buf);
		newlog->next = NULL;
		if (net->names==NULL) {
			net->names = newlog;
		} else {
			curr->next = newlog;
		}
		curr = newlog;
	}

	(void) apr_file_close(f);
}

static void StkAccessLoadConfig(apr_pool_t *p, server_rec *s, StkAccessConfig *pConfig){
	int result = 0;
	char Buf[MAXLOGIN];
	char *list_file,*pC;
	apr_file_t *f = NULL;
	NetList *curr, *newnet;

	const char *fname = ap_server_root_relative(p, CONFFILE);

	if (!fname) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
                     MODNAME ": Invalid config file path %s", fname);
        return;
    }
    if ((result = apr_file_open(&f, fname, APR_READ | APR_BUFFERED,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                     MODNAME ": can't read magic file %s", fname);
        return;
    }

	pConfig->networks = NULL;
	curr = NULL;
	
	while (apr_file_gets(Buf, MAXLOGIN, f) == APR_SUCCESS) {
		chomp(Buf);
		newnet = (NetList *)apr_pcalloc(p, sizeof *newnet);
		pC = strstr(Buf,"\t");
		if (!pC) {
			ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                     MODNAME ": Config string format error: (%s) ought to be <NetMask><Tab><Filename>", Buf);
			return;
		}
		*pC = '\0'; list_file = pC+1;
		StkAccessLoadList(p, s, list_file, newnet);
		newnet->netmask = (char *)apr_pcalloc(p, 16);
		strcpy(newnet->netmask,Buf);
		newnet->next = NULL;
		if (pConfig->networks==NULL) {
			pConfig->networks = newnet;
		} else {
			curr->next = newnet;
		}
		curr = newnet;
	}

	(void) apr_file_close(f);
}

static void *StkAccessCreateServerConfig(apr_pool_t *p, server_rec *s)
{
		
    StkAccessConfig *pConfig = (StkAccessConfig *)apr_pcalloc(p, sizeof *pConfig);
	
    pConfig->bEnabled = 0;

	StkAccessLoadConfig(p, s, pConfig); 
  
    return pConfig;
}


static LogList *StkAccessGetList(char *ip, NetList *root) {
	NetList *curr = root;
	LogList *found = NULL;
	char myip[16];
	while(curr) {
		strcpy(myip,ip);
		myip[strlen(curr->netmask)]='\0';
		if (!strcmp(myip,curr->netmask)) {
			found = curr->names;
			break;
		}
		curr = curr->next;
	}
	return found;
}

static int StkAccessCheckList(char *user_login, LogList *names) {
	LogList *curr = names;
	int found = 0;
	while(curr) {
		if (!_stricmp(user_login,curr->login)) {
			found = 1;
			break;
		}
		curr = curr->next;
	}
	return found;
}

static server_rec *srv;

static void StkAccessProcessBucket(ap_filter_t *f, apr_bucket *b) {
	char *pC, *pC1, *str, delim='&';
	char user_login[MAXLOGIN];
	int i;
	conn_rec *c = f->c;
	apr_bucket *d;
	LogList *names;
    StkAccessConfig *ptr =
    (StkAccessConfig *) ap_get_module_config(c->base_server->module_config,
                                           &access_filter_module);
    
	str = bucket_read_str(b);
	if (!str) return;

	if ((pC = strstr(str,USERFIELD))==NULL) {
		if ((pC = strstr(str,USERFIELD2))==NULL) return;
		pC += strlen(USERFIELD2)+1;
		delim='"';
	} else {
		pC += strlen(USERFIELD)+1;
	}
	pC1 = pC;
	i = 0;
	while(*pC1!=delim) user_login[i++] = *pC1++;
	user_login[i]='\0';
	srv =  c->base_server;
	names = StkAccessGetList(c->remote_ip, ptr->networks);
	if (!StkAccessCheckList(user_login, names)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
			"User %s from %s blocked",user_login,f->c->remote_ip) ;
		strnset(pC,'0',i);
		d = apr_bucket_heap_create(str,strlen(str),NULL,f->c->bucket_alloc);
		if (d) {
			APR_BUCKET_INSERT_BEFORE(b,d);
			APR_BUCKET_REMOVE(b);
		} else {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
			"Failed to create a bucket!") ;
		}
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
			"User %s from %s allowed", user_login,f->c->remote_ip) ;
	}
	
	free(str);
}


static apr_status_t StkAccessFilter(ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {


    apr_bucket *b;
    apr_status_t ret;
    conn_rec *c = f->c;
	   
    ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (ret == APR_SUCCESS) {
        for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) 
          StkAccessProcessBucket(f, b);
        
    } else {
        /*ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server
        "mod_access_filter: %s - %d", f->frec->name, ret) ;*/
        return ret;
    }

    return APR_SUCCESS ;
}

static int StkAccessPreConn(conn_rec *c, void *csd)
{
    StkAccessConfig *pConfig=(StkAccessConfig *)ap_get_module_config(c->base_server->module_config,
                                                     &access_filter_module);
	if(!pConfig->bEnabled||!pConfig->networks)
        	return OK;

	ap_add_input_filter(s_szStkAccessName,NULL,NULL,c);
	return OK;
}

static const char *StkAccessEnable(cmd_parms *cmd, void *dummy, int arg)
{
    StkAccessConfig *pConfig
      = (StkAccessConfig *)ap_get_module_config(cmd->server->module_config,
                             &access_filter_module);
    pConfig->bEnabled=arg;

    return NULL;
}

static const command_rec StkAccessCmds[] =
{
    AP_INIT_FLAG("UseAccessFilter", StkAccessEnable, NULL, RSRC_CONF,
                 "Run an access filter on this host"),
    { NULL }
};


static void StkAccessRegisterHooks(apr_pool_t *p)
{
   ap_register_input_filter(s_szStkAccessName, StkAccessFilter, NULL, AP_FTYPE_CONNECTION + 3) ;

   ap_hook_pre_connection(StkAccessPreConn, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA access_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    StkAccessCreateServerConfig,
    NULL,
    StkAccessCmds,
    StkAccessRegisterHooks
};
