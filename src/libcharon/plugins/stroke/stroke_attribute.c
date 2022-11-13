/*
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

/* vasprintf() */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <utils/utils.h>

#include <ndm/core.h>
#include <ndm/xml.h>

#include "stroke_attribute.h"
#include <daemon.h>
#include <collections/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_stroke_attribute_t private_stroke_attribute_t;

/**
 * private data of stroke_attribute
 */
struct private_stroke_attribute_t {

	/**
	 * public functions
	 */
	stroke_attribute_t public;

	/**
	 * list of pools, contains mem_pool_t
	 */
	linked_list_t *pools;

	/**
	 * List of connection specific attributes, as attributes_t
	 */
	linked_list_t *attrs;

	/**
	 * rwlock to lock access to pools
	 */
	rwlock_t *lock;
};

/**
 * Attributes assigned to a connection
 */
typedef struct {
	/** name of the connection */
	char *name;
	/** list of DNS attributes, as host_t */
	linked_list_t *dns;
} attributes_t;

/**
 * Destroy an attributes_t entry
 */
static void attributes_destroy(attributes_t *this)
{
	this->dns->destroy_offset(this->dns, offsetof(host_t, destroy));
	free(this->name);
	free(this);
}

/**
 * find a pool by name
 */
static mem_pool_t *find_pool(private_stroke_attribute_t *this, char *name)
{
	enumerator_t *enumerator;
	mem_pool_t *current, *found = NULL;

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(name, current->get_name(current)))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

static host_t *get_address_ndm(const char *map, const char *id,
							   const chunk_t *remote, const char *remote_id)
{
	struct ndm_core_t *core;
	struct ndm_core_response_t *resp;
	const struct ndm_xml_node_t *root;
	const struct ndm_xml_node_t *node;
	host_t *result = NULL;
	char remote_addr[INET_ADDRSTRLEN + 1];
	const char *request_args[] = {
		"name", map,
		"user", id,
		"remote-peer", remote_addr,
		"remote-peer-id", remote_id,
		NULL
	};

	memset(remote_addr, 0, sizeof(remote_addr));

	if (inet_ntop(AF_INET, remote->ptr,
			remote_addr, sizeof(remote_addr)) == NULL)
	{
		DBG1(DBG_CFG, "unable to convert IPv4 address to string");
		return NULL;
	}

	core = ndm_core_open(
		"strongswan-stroke/ci", 1000, NDM_CORE_DEFAULT_CACHE_MAX_SIZE);

	if (core == NULL)
	{
		DBG1(DBG_CFG, "NDM connection failed");
		return NULL;
	}

	if ((resp = ndm_core_request(core,
			NDM_CORE_REQUEST_EXECUTE, NDM_CORE_MODE_NO_CACHE, request_args,
			"crypto map virtual-ip alloc-address")) == NULL)
	{
		DBG1(DBG_CFG, "NDM request failed");
		ndm_core_response_free(&resp);
		ndm_core_close(&core);
		return NULL;
	}

	if (!ndm_core_response_is_ok(resp))
	{
		if (!ndm_core_last_message_received(core))
		{
			DBG1(DBG_CFG, "NDM give no answer");
		} else
		{
			DBG1(DBG_CFG, "unable to obtain lease");
		}

		ndm_core_response_free(&resp);
		ndm_core_close(&core);

		return NULL;
	}

	root = ndm_core_response_root(resp);

	if (root == NULL ||
		ndm_xml_node_type(root) != NDM_XML_NODE_TYPE_ELEMENT ||
		strcmp(ndm_xml_node_name(root), "response") ||
		(node = ndm_xml_node_first_child(root, NULL)) == NULL)
	{
		DBG1(DBG_CFG, "NDM response is invalid");
		ndm_core_response_free(&resp);
		ndm_core_close(&core);
		return NULL;
	}

	if (!strcmp(ndm_xml_node_name(node), "allocated-address"))
	{
		result = host_create_from_string_and_family(
			(char*)ndm_xml_node_value(node), AF_INET, 0);
	} else
	{
		DBG1(DBG_CFG, "no free address found");
		ndm_core_response_free(&resp);
		ndm_core_close(&core);
		return NULL;
	}

	ndm_core_response_free(&resp);
	ndm_core_close(&core);

	return result;
}

static char *get_id_str(char *fmt, ...)
{
	char *str;
	va_list args;

	va_start(args, fmt);
	if (vasprintf(&str, fmt, args) == -1)
	{
		str = NULL;
	}
	va_end(args);

	return str;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_stroke_attribute_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	host_t *requested)
{
	identification_t *id, *remote_id;
	host_t *addr, *peer;
	chunk_t remote_peer;
	char *name;
	char *id_str, *remote_id_str;

	if (requested->get_family(requested) != AF_INET)
	{
		return NULL;
	}

	name = ike_sa->get_name(ike_sa);
	id = ike_sa->get_other_eap_id(ike_sa);
	remote_id = ike_sa->get_other_id(ike_sa);
	peer = ike_sa->get_other_host(ike_sa);
	remote_peer = peer->get_address(peer);

	id_str = get_id_str("%Y", id);

	if (id_str == NULL)
	{
		DBG1(DBG_CFG, "unable to print ID");
		return NULL;
	}

	remote_id_str = get_id_str("%Y", remote_id);

	if (remote_id_str == NULL)
	{
		DBG1(DBG_CFG, "unable to print remote ID");
		free(id_str);
		return NULL;
	}

	this->lock->read_lock(this->lock);

	addr = get_address_ndm(name, id_str, &remote_peer, remote_id_str);

	this->lock->unlock(this->lock);

	free(id_str);
	free(remote_id_str);

	return addr;
}

METHOD(attribute_provider_t, release_address, bool,
	private_stroke_attribute_t *this, linked_list_t *pools, host_t *address,
	ike_sa_t *ike_sa)
{
	return TRUE;
}

CALLBACK(attr_filter, bool,
	void *lock, enumerator_t *orig, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;
	host_t *host;

	VA_ARGS_VGET(args, type, data);

	while (orig->enumerate(orig, &host))
	{
		switch (host->get_family(host))
		{
			case AF_INET:
				*type = INTERNAL_IP4_DNS;
				break;
			case AF_INET6:
				*type = INTERNAL_IP6_DNS;
				break;
			default:
				continue;
		}
		*data = host->get_address(host);
		return TRUE;
	}
	return FALSE;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_stroke_attribute_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, linked_list_t *vips)
{
	peer_cfg_t *peer_cfg;
	enumerator_t *enumerator;
	attributes_t *attr;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa)
	{
		peer_cfg = ike_sa->get_peer_cfg(ike_sa);
		this->lock->read_lock(this->lock);
		enumerator = this->attrs->create_enumerator(this->attrs);
		while (enumerator->enumerate(enumerator, &attr))
		{
			if (streq(attr->name, peer_cfg->get_name(peer_cfg)))
			{
				enumerator->destroy(enumerator);
				return enumerator_create_filter(
									attr->dns->create_enumerator(attr->dns),
									attr_filter, this->lock,
									(void*)this->lock->unlock);
			}
		}
		enumerator->destroy(enumerator);
		this->lock->unlock(this->lock);
	}
	return enumerator_create_empty();
}

METHOD(stroke_attribute_t, add_pool, void,
	private_stroke_attribute_t *this, mem_pool_t *pool)
{
	enumerator_t *enumerator;
	mem_pool_t *current;
	host_t *base;
	int size;

	base = pool->get_base(pool);
	size = pool->get_size(pool);

	this->lock->write_lock(this->lock);

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (base && current->get_base(current) &&
			base->ip_equals(base, current->get_base(current)) &&
			size == current->get_size(current))
		{
			DBG1(DBG_CFG, "reusing virtual IP address pool %s",
				 current->get_name(current));
			pool->destroy(pool);
			pool = NULL;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (pool)
	{
		if (base)
		{
			DBG1(DBG_CFG, "adding virtual IP address pool %s",
				 pool->get_name(pool));
		}
		this->pools->insert_last(this->pools, pool);
	}

	this->lock->unlock(this->lock);
}

METHOD(stroke_attribute_t, add_dns, void,
	private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	if (msg->add_conn.other.dns)
	{
		enumerator_t *enumerator;
		attributes_t *attr = NULL;
		host_t *host;
		char *token;

		enumerator = enumerator_create_token(msg->add_conn.other.dns, ",", " ");
		while (enumerator->enumerate(enumerator, &token))
		{
			host = host_create_from_string(token, 0);
			if (host)
			{
				if (!attr)
				{
					INIT(attr,
						.name = strdup(msg->add_conn.name),
						.dns = linked_list_create(),
					);
				}
				attr->dns->insert_last(attr->dns, host);
			}
			else
			{
				DBG1(DBG_CFG, "ignoring invalid DNS address '%s'", token);
			}
		}
		enumerator->destroy(enumerator);
		if (attr)
		{
			this->lock->write_lock(this->lock);
			this->attrs->insert_last(this->attrs, attr);
			this->lock->unlock(this->lock);
		}
	}
}

METHOD(stroke_attribute_t, del_dns, void,
	private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator;
	attributes_t *attr;

	this->lock->write_lock(this->lock);

	enumerator = this->attrs->create_enumerator(this->attrs);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (streq(msg->del_conn.name, attr->name))
		{
			this->attrs->remove_at(this->attrs, enumerator);
			attributes_destroy(attr);
			break;
		}
	}
	enumerator->destroy(enumerator);

	this->lock->unlock(this->lock);
}

CALLBACK(pool_filter, bool,
	void *lock, enumerator_t *orig, va_list args)
{
	mem_pool_t *pool;
	const char **name;
	u_int *size, *online, *offline;

	VA_ARGS_VGET(args, name, size, online, offline);

	while (orig->enumerate(orig, &pool))
	{
		if (pool->get_size(pool) == 0)
		{
			continue;
		}
		*name = pool->get_name(pool);
		*size = pool->get_size(pool);
		*online = pool->get_online(pool);
		*offline = pool->get_offline(pool);
		return TRUE;
	}
	return FALSE;
}

METHOD(stroke_attribute_t, create_pool_enumerator, enumerator_t*,
	private_stroke_attribute_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->pools->create_enumerator(this->pools),
									pool_filter,
									this->lock, (void*)this->lock->unlock);
}

METHOD(stroke_attribute_t, create_lease_enumerator, enumerator_t*,
	private_stroke_attribute_t *this, char *name)
{
	mem_pool_t *pool;
	this->lock->read_lock(this->lock);
	pool = find_pool(this, name);
	if (!pool)
	{
		this->lock->unlock(this->lock);
		return NULL;
	}
	return enumerator_create_cleaner(pool->create_lease_enumerator(pool),
									 (void*)this->lock->unlock, this->lock);
}

METHOD(stroke_attribute_t, destroy, void,
	private_stroke_attribute_t *this)
{
	this->lock->destroy(this->lock);
	this->pools->destroy_offset(this->pools, offsetof(mem_pool_t, destroy));
	this->attrs->destroy_function(this->attrs, (void*)attributes_destroy);
	free(this);
}

/*
 * see header file
 */
stroke_attribute_t *stroke_attribute_create()
{
	private_stroke_attribute_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.add_pool = _add_pool,
			.add_dns = _add_dns,
			.del_dns = _del_dns,
			.create_pool_enumerator = _create_pool_enumerator,
			.create_lease_enumerator = _create_lease_enumerator,
			.destroy = _destroy,
		},
		.pools = linked_list_create(),
		.attrs = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
