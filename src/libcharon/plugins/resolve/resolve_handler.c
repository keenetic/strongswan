/*
 * Copyright (C) 2012-2016 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "resolve_handler.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utils/debug.h>
#include <utils/process.h>
#include <collections/array.h>
#include <threading/mutex.h>

#define NDM_FEEDBACK "/tmp/ipsec/charon.feedback"

/* path to resolvconf executable */
#define RESOLVCONF_EXEC "/sbin/resolvconf"

/* default prefix used for resolvconf interfaces (should have high prio) */
#define RESOLVCONF_PREFIX "lo.inet.ipsec."

typedef struct private_resolve_handler_t private_resolve_handler_t;

/**
 * Private data of an resolve_handler_t object.
 */
struct private_resolve_handler_t {

	/**
	 * Public resolve_handler_t interface.
	 */
	resolve_handler_t public;

	/**
	 * resolv.conf file to use
	 */
	char *file;

	/**
	 * Use resolvconf instead of writing directly to resolv.conf
	 */
	bool use_resolvconf;

	/**
	 * Prefix to be used for interface names sent to resolvconf
	 */
	char *iface_prefix;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;

	/**
	 * Reference counting for DNS servers dns_server_t
	 */
	array_t *servers;
};

/**
 * Reference counting for DNS servers
 */
typedef struct {

	/**
	 * DNS server address
	 */
	host_t *server;

	/**
	 * Reference count
	 */
	u_int refcount;

} dns_server_t;

static void invoke_feedback(char* connection, host_t *addr, bool install)
{
	FILE *shell = NULL;
	process_t *process = NULL;
	char *envp[128] = { 0 };

	char action[32] = { 0 };
	char host[128] = { 0 };
	char *argv[5] = {NDM_FEEDBACK, action, connection, host, NULL};
	int out;

	snprintf(action, sizeof(action), install ? "dns4-add" : "dns4-remove");
	snprintf(host, sizeof(host), "%H", addr);

	process = process_start(argv, envp, NULL, &out, NULL, TRUE);
	if (process)
	{
		shell = fdopen(out, "r");
		if (shell)
		{
			while (TRUE)
			{
				char resp[128];

				if (fgets(resp, sizeof(resp), shell) == NULL)
				{
					if (ferror(shell))
					{
						DBG1(DBG_CHD, "error reading from feedback script");
					}
					break;
				}
				else
				{
					char *e = resp + strlen(resp);
					if (e > resp && e[-1] == '\n')
					{
						e[-1] = '\0';
					}
					DBG2(DBG_CHD, "feedback: %s", resp);
				}
			}
			fclose(shell);
		}
		else
		{
			close(out);
		}
		process->wait(process, NULL);
	}
}

METHOD(attribute_handler_t, handle, bool,
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *addr;
	bool handled = FALSE;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			addr = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			addr = host_create_from_chunk(AF_INET6, data, 0);
			break;
		default:
			return FALSE;
	}

	if (!addr || addr->is_anyaddr(addr))
	{
		DESTROY_IF(addr);
		return FALSE;
	}

	this->mutex->lock(this->mutex);

	if (type == INTERNAL_IP4_DNS && ike_sa != NULL)
	{
		invoke_feedback(ike_sa->get_name(ike_sa), addr, TRUE);
		handled = TRUE;
	}

	this->mutex->unlock(this->mutex);
	addr->destroy(addr);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed");
	}
	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *addr;
	int family;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return;
	}
	addr = host_create_from_chunk(family, data, 0);

	this->mutex->lock(this->mutex);

	if (type == INTERNAL_IP4_DNS && ike_sa != NULL)
	{
		invoke_feedback(ike_sa->get_name(ike_sa), addr, FALSE);
	}

	this->mutex->unlock(this->mutex);

	addr->destroy(addr);
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** request IPv4 DNS? */
	bool v4;
	/** request IPv6 DNS? */
	bool v6;
} attribute_enumerator_t;

METHOD(enumerator_t, attribute_enumerate, bool,
	attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->v4)
	{
		*type = INTERNAL_IP4_DNS;
		*data = chunk_empty;
		this->v4 = FALSE;
		return TRUE;
	}
	if (this->v6)
	{
		*type = INTERNAL_IP6_DNS;
		*data = chunk_empty;
		this->v6 = FALSE;
		return TRUE;
	}
	return FALSE;
}

/**
 * Check if a list has a host of given family
 */
static bool has_host_family(linked_list_t *list, int family)
{
	enumerator_t *enumerator;
	host_t *host;
	bool found = FALSE;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (host->get_family(host) == family)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_resolve_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _attribute_enumerate,
			.destroy = (void*)free,
		},
		.v4 = has_host_family(vips, AF_INET),
		.v6 = has_host_family(vips, AF_INET6),
	);
	return &enumerator->public;
}

METHOD(resolve_handler_t, destroy, void,
	private_resolve_handler_t *this)
{
	array_destroy(this->servers);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
resolve_handler_t *resolve_handler_create()
{
	private_resolve_handler_t *this;
	struct stat st;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.file = lib->settings->get_str(lib->settings, "%s.plugins.resolve.file",
									   RESOLV_CONF, lib->ns),
	);

	if (stat(RESOLVCONF_EXEC, &st) == 0)
	{
		this->use_resolvconf = TRUE;
		this->iface_prefix = lib->settings->get_str(lib->settings,
								"%s.plugins.resolve.resolvconf.iface_prefix",
								RESOLVCONF_PREFIX, lib->ns);
	}

	return &this->public;
}
