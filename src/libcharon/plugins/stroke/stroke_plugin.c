/*
 * Copyright (C) 2008 Martin Willi
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

#include "stroke_plugin.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <library.h>
#include <daemon.h>
#include <processing/jobs/callback_job.h>
#include "stroke_socket.h"

typedef struct private_stroke_plugin_t private_stroke_plugin_t;

/**
 * private data of stroke_plugin
 */
struct private_stroke_plugin_t {

	/**
	 * public functions
	 */
	stroke_plugin_t public;

	/**
	 * stroke socket, receives strokes
	 */
	stroke_socket_t *socket;
};

#define UPDATE_STATS_INTERVAL 3

#define IPSEC_PATH "/tmp/ipsec/stats/"

#define FILENAME_BUFFER 128

static void mktmpfile(char * out, unsigned int len, char * conn)
{
	snprintf(out, len, "%s%s_temp", IPSEC_PATH, conn);
}

static void mkfile(char * out, unsigned int len, char * conn)
{
	snprintf(out, len, "%s%s", IPSEC_PATH, conn);
}

static void mktmpfilesa(char * out, unsigned int len, char * conn)
{
	snprintf(out, len, "%ssa_%s_temp", IPSEC_PATH, conn);
}

static void mkfilesa(char * out, unsigned int len, char * conn)
{
	snprintf(out, len, "%ssa_%s", IPSEC_PATH, conn);
}

static void update_auth(FILE *out, peer_cfg_t *peer_cfg, bool local)
{
	enumerator_t *enumerator, *rules;
	auth_rule_t rule;
	auth_cfg_t *auth;
	auth_class_t auth_class;
	identification_t *id;
	certificate_t *cert;
	cert_validation_t valid;
	char *name;

	name = peer_cfg->get_name(peer_cfg);

	fprintf(out, "auth%s\n", local ? "local" : "remote");
	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg, local);
	while (enumerator->enumerate(enumerator, &auth))
	{
		fprintf(out, "stage\n");
		id = auth->get(auth, AUTH_RULE_IDENTITY);
		if (id)
		{
			fprintf(out, "%Y\n", id);
		} else
		{
			fprintf(out, "any\n");
		}
		auth_class = (uintptr_t)auth->get(auth, AUTH_RULE_AUTH_CLASS);
		fprintf(out, "%u\n", auth_class);

		if (auth_class == AUTH_CLASS_XAUTH)
		{
			fprintf(out, "%s\n", auth->get(auth, AUTH_RULE_XAUTH_BACKEND) ?: "any");
			id = auth->get(auth, AUTH_RULE_XAUTH_IDENTITY);
			if (id)
			{
				fprintf(out, "%Y\n", id);
			} else
			{
				fprintf(out, "any\n");
			}
		} else 
		{
			fprintf(out, "none\nany\n");
		}
	}
	fflush(out);
	enumerator->destroy(enumerator);
}

static void update_connections(void)
{
	enumerator_t *enumerator, *children;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	ike_sa_t *ike_sa;
	linked_list_t *my_ts, *other_ts;
	bool first, found = FALSE;
	u_int half_open;
	peer_cfg_t *peer_cfg;
	ike_version_t ike_version;
	char *pool;
	host_t *host;
	u_int32_t dpd;
	time_t since, now;
	u_int size, online, offline, i;

	enumerator = charon->backends->create_peer_cfg_enumerator(
					charon->backends, NULL, NULL, NULL, NULL, IKE_ANY);
	while (enumerator->enumerate(enumerator, &peer_cfg))
	{
		char *my_addr, *other_addr;
		char tmpfilename[FILENAME_BUFFER];
		char filename[FILENAME_BUFFER];
		FILE * fd = NULL;

		mktmpfile(tmpfilename, sizeof(tmpfilename), peer_cfg->get_name(peer_cfg));
		mkfile(filename, sizeof(filename), peer_cfg->get_name(peer_cfg));

		fd = fopen(tmpfilename, "w");

		if (fd != NULL)
		{
			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			ike_version = peer_cfg->get_ike_version(peer_cfg);
			my_addr = ike_cfg->get_my_addr(ike_cfg);
			other_addr = ike_cfg->get_other_addr(ike_cfg);
			fprintf(fd, "%d\n%d\n%s\n%s\n%u\n", time(NULL), time_monotonic(NULL),
				my_addr, other_addr, ike_version);

			if (ike_version == IKEV1 && peer_cfg->use_aggressive(peer_cfg))
			{
				fprintf(fd, "agg\n");
			} else
			{
				fprintf(fd, "norm\n");
			}

			dpd = peer_cfg->get_dpd(peer_cfg);
			if (dpd)
			{
				fprintf(fd, "%u\n", dpd);
			} else
			{
				fprintf(fd, "0\n");
			}

			update_auth(fd, peer_cfg, TRUE);
			update_auth(fd, peer_cfg, FALSE);

			children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (children->enumerate(children, &child_cfg))
			{
				my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
				other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
				fprintf(fd, "child\n%#R\n%#R\n%N\n", my_ts, other_ts,
						ipsec_mode_names, child_cfg->get_mode(child_cfg));
				my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
				other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));

				if (dpd)
				{
					fprintf(fd, "%u\n", child_cfg->get_dpd_action(child_cfg));
				} else
				{
					fprintf(fd, "0\n");
				}
			}
			children->destroy(children);

			fflush(fd);
			fclose(fd);
			rename(tmpfilename, filename);
		}
	}
	enumerator->destroy(enumerator);
}

void update_ike_sa(FILE *out, ike_sa_t *ike_sa)
{
	proposal_t *ike_proposal;
	identification_t *eap_id;
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	time_t now = time_monotonic(NULL);

	fprintf(out, "%d\n%u\n",ike_sa->get_unique_id(ike_sa), ike_sa->get_state(ike_sa));

	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		time_t established;

		established = ike_sa->get_statistic(ike_sa, STAT_ESTABLISHED);
		fprintf(out, "%d\n", established);
	} else
	{
		fprintf(out, "0\n");
	}

	fprintf(out, "%H\n%Y\n%H\n%Y\n",
			ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
			ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));

	ike_proposal = ike_sa->get_proposal(ike_sa);

	fprintf(out, "%u\n%.16"PRIx64"\n%.16"PRIx64"\n%u\n",
			ike_sa->get_version(ike_sa),
			id->get_initiator_spi(id),
			id->get_responder_spi(id),
			id->is_initiator(id) ? 1 : 0);

	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		time_t rekey, reauth;

		rekey = ike_sa->get_statistic(ike_sa, STAT_REKEY);
		reauth = ike_sa->get_statistic(ike_sa, STAT_REAUTH);

		fprintf(out, "%d\n", rekey);
		fprintf(out, "%d\n", reauth);

	} else
	{
		fprintf(out, "0\n0\n");
	}


	if (ike_proposal)
	{
		char buf[BUF_LEN];

		snprintf(buf, BUF_LEN, "%P", ike_proposal);
		fprintf(out, "%s", buf + 4);
	} else
	{
		fprintf(out, "NONE");
	}
}

static void update_child_sa(FILE *out, child_sa_t *child_sa)
{
	time_t use_in, use_out, rekey, now;
	u_int64_t bytes_in, bytes_out, packets_in, packets_out;
	proposal_t *proposal;
	linked_list_t *my_ts, *other_ts;
	child_cfg_t *config;

	config = child_sa->get_config(child_sa);
	now = time_monotonic(NULL);

	fprintf(out, "%d\n%u\n%u\n%u\n",
			child_sa->get_unique_id(child_sa),
			child_sa->get_state(child_sa),
			child_sa->get_mode(child_sa),
			child_sa->get_reqid(child_sa));

	if (child_sa->get_state(child_sa) == CHILD_INSTALLED)
	{
		fprintf(out, "%u\n%u\n%.8x\n%.8x\n",
				child_sa->get_protocol(child_sa),
				child_sa->has_encap(child_sa) ? 1 : 0,
				ntohl(child_sa->get_spi(child_sa, TRUE)),
				ntohl(child_sa->get_spi(child_sa, FALSE)));

		proposal = child_sa->get_proposal(child_sa);
		if (proposal)
		{
			u_int16_t encr_alg = ENCR_UNDEFINED, int_alg = AUTH_UNDEFINED;
			u_int16_t encr_size = 0, int_size = 0;
			u_int16_t esn = NO_EXT_SEQ_NUMBERS;
			u_int16_t dh = MODP_NONE;
			bool first = TRUE;

			proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM,
									&encr_alg, &encr_size);
			proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM,
									&int_alg, &int_size);
			proposal->get_algorithm(proposal, EXTENDED_SEQUENCE_NUMBERS,
									&esn, NULL);
			proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP,
									&dh, NULL);

			if (encr_alg != ENCR_UNDEFINED)
			{
				fprintf(out, "%N", encryption_algorithm_names, encr_alg);
				first = FALSE;
				if (encr_size)
				{
					fprintf(out, "=%u", encr_size);
				}
			}
			if (int_alg != AUTH_UNDEFINED)
			{
				if (!first)
				{
					fprintf(out, "/");
					first = FALSE;
				}
				fprintf(out, "%N", integrity_algorithm_names, int_alg);
				if (int_size)
				{
					fprintf(out, "_%u", int_size);
				}
			}
			if (esn == EXT_SEQ_NUMBERS)
			{
				fprintf(out, "/ESN");
			} else
			{
				fprintf(out, "/NOESN");
			}
			if (dh != MODP_NONE)
			{
				fprintf(out, "/%N", diffie_hellman_group_names, dh);
			} else
			{
				fprintf(out, "/MODP_NONE");
			}
			fprintf(out, "\n");
		} else
		{
			fprintf(out, "none\n");
		}

		child_sa->get_usestats(child_sa, TRUE,
							   &use_in, &bytes_in, &packets_in);
		fprintf(out, "%" PRIu64 "\n", bytes_in);
		if (use_in)
		{
			fprintf(out, "%" PRIu64 "\n%" PRIu64 "\n",
					packets_in, (u_int64_t)(now - use_in));
		} else
		{
			fprintf(out, "0\n0\n");
		}

		child_sa->get_usestats(child_sa, FALSE,
							   &use_out, &bytes_out, &packets_out);
		fprintf(out, "%" PRIu64 "\n", bytes_out);
		if (use_out)
		{
			fprintf(out, "%" PRIu64 "\n%" PRIu64 "\n",
					packets_out, (u_int64_t)(now - use_out));
		} else
		{
			fprintf(out, "0\n0\n");
		}

		rekey = child_sa->get_lifetime(child_sa, FALSE);
		fprintf(out, "%d\n", rekey);
	}
	else if (child_sa->get_state(child_sa) == CHILD_REKEYING ||
			 child_sa->get_state(child_sa) == CHILD_REKEYED)
	{
		fprintf(out, "0\n0\n0\n0\nnone\n0\n0\n0\n0\n0\n0\n");
		rekey = child_sa->get_lifetime(child_sa, TRUE);
		fprintf(out, "%d\n", rekey);
	}

	my_ts = linked_list_create_from_enumerator(
							child_sa->create_ts_enumerator(child_sa, TRUE));
	other_ts = linked_list_create_from_enumerator(
							child_sa->create_ts_enumerator(child_sa, FALSE));
	fprintf(out, "%#R\n%#R", my_ts, other_ts);
	my_ts->destroy(my_ts);
	other_ts->destroy(other_ts);
}


static void update_sa(void)
{
	enumerator_t *enumerator, *children;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	ike_sa_t *ike_sa;
	linked_list_t *my_ts, *other_ts;
	bool first, found = FALSE;
	u_int half_open;

	enumerator = charon->controller->create_ike_sa_enumerator(
													charon->controller, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		FILE * fd = NULL;
		char tmpfile[FILENAME_BUFFER], file[FILENAME_BUFFER];

		mktmpfilesa(tmpfile, sizeof(tmpfile), ike_sa->get_name(ike_sa));
		mkfilesa(file, sizeof(file), ike_sa->get_name(ike_sa));

		fd = fopen(tmpfile, "w");

		if (fd != NULL)
		{
			fprintf(fd, "%d\n%d\n", time(NULL), time_monotonic(NULL));

			fprintf(fd, "ikesa\n");
			update_ike_sa(fd, ike_sa);

			enumerator_t *children = ike_sa->create_child_sa_enumerator(ike_sa);

			while (children->enumerate(children, (void**)&child_sa))
			{
				fprintf(fd, "\nchildsa\n");
				update_child_sa(fd, child_sa);
			}
			children->destroy(children);

			fflush(fd);
			fclose(fd);
			rename(tmpfile, file);
		}
	}
	enumerator->destroy(enumerator);
}

static void update(void)
{
	struct stat st = {0};
	if (stat(IPSEC_PATH, &st) == -1) {
		mkdir(IPSEC_PATH, 0777);
	}
	update_connections();
	update_sa();
}

static job_requeue_t update_statistics(private_stroke_plugin_t *this)
{
	update();
	lib->scheduler->schedule_job(lib->scheduler, (job_t*)
			callback_job_create((callback_job_cb_t)update_statistics,
			this, NULL, NULL), UPDATE_STATS_INTERVAL);
	DBG2(DBG_CFG, "statistics was written");
	return JOB_REQUEUE_NONE;
}

METHOD(plugin_t, get_name, char*,
	private_stroke_plugin_t *this)
{
	return "stroke";
}

/**
 * Register stroke plugin features
 */
static bool register_stroke(private_stroke_plugin_t *this,
							plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		lib->scheduler->schedule_job(lib->scheduler, (job_t*)
				callback_job_create((callback_job_cb_t)update_statistics,
				this, NULL, NULL), 1);
		this->socket = stroke_socket_create();
		return this->socket != NULL;
	}
	else
	{
		DESTROY_IF(this->socket);
		return TRUE;
	}
}

METHOD(plugin_t, get_features, int,
	private_stroke_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)register_stroke, NULL),
			PLUGIN_PROVIDE(CUSTOM, "stroke"),
				PLUGIN_SDEPEND(PRIVKEY, KEY_RSA),
				PLUGIN_SDEPEND(PRIVKEY, KEY_ECDSA),
				PLUGIN_SDEPEND(PRIVKEY, KEY_DSA),
				PLUGIN_SDEPEND(PRIVKEY, KEY_BLISS),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_ANY),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_X509),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_X509_CRL),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_X509_AC),
				PLUGIN_SDEPEND(CERT_DECODE, CERT_TRUSTED_PUBKEY),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_stroke_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *stroke_plugin_create()
{
	private_stroke_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
