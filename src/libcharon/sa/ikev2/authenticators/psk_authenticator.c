/*
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
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

#include "psk_authenticator.h"

#include <daemon.h>
#include <utils/utils/memory.h>
#include <encoding/payloads/auth_payload.h>
#include <sa/ikev2/keymat_v2.h>

typedef struct private_psk_authenticator_t private_psk_authenticator_t;

/**
 * Private data of an psk_authenticator_t object.
 */
struct private_psk_authenticator_t {

	/**
	 * Public authenticator_t interface.
	 */
	psk_authenticator_t public;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * nonce to include in AUTH calculation
	 */
	chunk_t nonce;

	/**
	 * IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t ike_sa_init;

	/**
	 * Reserved bytes of ID payload
	 */
	char reserved[3];
};

METHOD(authenticator_t, build, status_t,
	private_psk_authenticator_t *this, message_t *message)
{
	identification_t *my_id, *other_id;
	auth_payload_t *auth_payload;
	shared_key_t *key;
	chunk_t auth_data;
	keymat_v2_t *keymat;
	char *ike_sa_name;

	keymat = (keymat_v2_t*)this->ike_sa->get_keymat(this->ike_sa);

	/* first of all, try to search linked PSKs */
	ike_sa_name = this->ike_sa->get_name(this->ike_sa);
	key = lib->credmgr->get_shared_crypto_map(lib->credmgr, SHARED_IKE,
		ike_sa_name);
	if (key != NULL)
	{
		DBG1(DBG_IKE, "found linked key for crypto map '%s'", ike_sa_name);
	} else
	{
		DBG1(DBG_IKE, "linked key for crypto map '%s' is not found, still searching", ike_sa_name);
		my_id = this->ike_sa->get_my_id(this->ike_sa);
		other_id = this->ike_sa->get_other_id(this->ike_sa);
		DBG1(DBG_IKE, "authentication of '%Y' (myself) with %N",
			 my_id, auth_method_names, AUTH_PSK);
		key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE, my_id, other_id);
		if (key == NULL)
		{
			DBG1(DBG_IKE, "no shared key found for '%Y' - '%Y'", my_id, other_id);
			return NOT_FOUND;
		}
	}

	if (!keymat->get_psk_sig(keymat, FALSE, this->ike_sa_init, this->nonce,
						key->get_key(key), my_id, this->reserved, &auth_data))
	{
		key->destroy(key);
		return FAILED;
	}
	key->destroy(key);
	DBG2(DBG_IKE, "successfully created shared key MAC");
	auth_payload = auth_payload_create();
	auth_payload->set_auth_method(auth_payload, AUTH_PSK);
	auth_payload->set_data(auth_payload, auth_data);
	chunk_free(&auth_data);
	message->add_payload(message, (payload_t*)auth_payload);

	return SUCCESS;
}

METHOD(authenticator_t, process, status_t,
	private_psk_authenticator_t *this, message_t *message)
{
	chunk_t auth_data, recv_auth_data;
	identification_t *my_id, *other_id;
	auth_payload_t *auth_payload;
	auth_cfg_t *auth;
	shared_key_t *key;
	enumerator_t *enumerator;
	bool authenticated = FALSE;
	int keys_found = 0;
	keymat_v2_t *keymat;
	identification_t *local_ndm_id = NULL;
	identification_t *remote_ndm_id = identification_create_from_string(NULL);
	char local_id[1024];
	id_match_t ndm_match_local;

	auth_payload = (auth_payload_t*)message->get_payload(message, PLV2_AUTH);
	if (!auth_payload)
	{
		return FAILED;
	}
	keymat = (keymat_v2_t*)this->ike_sa->get_keymat(this->ike_sa);
	recv_auth_data = auth_payload->get_data(auth_payload);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);

	/* Firstly try to search for linked crypto map keys */

	memset(local_id, 0, sizeof(local_id));
	snprintf(local_id, sizeof(local_id), "cmap:%s", this->ike_sa->get_name(this->ike_sa));
	local_ndm_id = identification_create_from_string(local_id);

	enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
												SHARED_IKE, local_ndm_id, remote_ndm_id);
	while (!authenticated && enumerator->enumerate(enumerator, &key, &ndm_match_local, NULL))
	{
		if (ndm_match_local == ID_MATCH_PERFECT)
		{
			if (!keymat->get_psk_sig(keymat, TRUE, this->ike_sa_init, this->nonce,
						key->get_key(key), other_id, this->reserved, &auth_data))
			{
				continue;
			}
			if (auth_data.len && chunk_equals_const(auth_data, recv_auth_data))
			{
				DBG1(DBG_IKE, "authentication of '%Y' with %N successful with linked key",
					 other_id, auth_method_names, AUTH_PSK);
				authenticated = TRUE;
			}
			chunk_free(&auth_data);
		}
	}
	enumerator->destroy(enumerator);

	DESTROY_IF(local_ndm_id);
	DESTROY_IF(remote_ndm_id);

	/* Linked key was not found, try to use another */

	if (!authenticated)
	{
		DBG1(DBG_IKE, "linked key for crypto map '%s' is not found, still searching",
			this->ike_sa->get_name(this->ike_sa));

		enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
													SHARED_IKE, my_id, other_id);
		while (!authenticated && enumerator->enumerate(enumerator, &key, NULL, NULL))
		{
			keys_found++;

			if (!keymat->get_psk_sig(keymat, TRUE, this->ike_sa_init, this->nonce,
						key->get_key(key), other_id, this->reserved, &auth_data))
			{
				continue;
			}
			if (auth_data.len && chunk_equals_const(auth_data, recv_auth_data))
			{
				DBG1(DBG_IKE, "authentication of '%Y' with %N successful",
					 other_id, auth_method_names, AUTH_PSK);
				authenticated = TRUE;
			}
			chunk_free(&auth_data);
		}
		enumerator->destroy(enumerator);
	}

	if (!authenticated)
	{
		if (keys_found == 0)
		{
			DBG1(DBG_IKE, "no shared key found for '%Y' - '%Y'", my_id, other_id);
			return NOT_FOUND;
		}
		DBG1(DBG_IKE, "tried %d shared key%s for '%Y' - '%Y', but MAC mismatched",
			 keys_found, keys_found == 1 ? "" : "s", my_id, other_id);
		return FAILED;
	}

	auth = this->ike_sa->get_auth_cfg(this->ike_sa, FALSE);
	auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
	return SUCCESS;
}

METHOD(authenticator_t, destroy, void,
	private_psk_authenticator_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
psk_authenticator_t *psk_authenticator_create_builder(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_init,
									char reserved[3])
{
	private_psk_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build,
				.process = (void*)return_failed,
				.is_mutual = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.ike_sa_init = sent_init,
		.nonce = received_nonce,
	);
	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public;
}

/*
 * Described in header.
 */
psk_authenticator_t *psk_authenticator_create_verifier(ike_sa_t *ike_sa,
									chunk_t sent_nonce, chunk_t received_init,
									char reserved[3])
{
	private_psk_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = (void*)return_failed,
				.process = _process,
				.is_mutual = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.ike_sa_init = received_init,
		.nonce = sent_nonce,
	);
	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public;
}
