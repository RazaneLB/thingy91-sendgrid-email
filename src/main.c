/*
 * Thingy:91 - Envoi d'un e-mail via LTE-M / NB-IoT (eSIM iBasis)
 * en utilisant l'API REST de SendGrid en HTTPS (TLS offloadé par le modem nRF9160).
 *
 * nRF Connect SDK 3.2.1
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <string.h>
#include <stdio.h>

LOG_MODULE_REGISTER(email_sender, LOG_LEVEL_INF);

/* ---------- A PERSONNALISER ---------- */
#define SENDGRID_HOST     "api.sendgrid.com"
#define SENDGRID_PORT     "443"
#define SENDGRID_API_KEY  "COLLEZ_ICI_VOTRE_CLE_API_SENDGRID"
#define EMAIL_FROM        "expediteur_verifie@votredomaine.com" /* doit être vérifié dans SendGrid */
#define EMAIL_TO          "destinataire@example.com"
#define EMAIL_SUBJECT     "Alerte depuis le Thingy:91"
#define EMAIL_BODY        "Ce message a ete envoye automatiquement par le Thingy:91 via LTE-M."

/* Numéro de sec_tag arbitraire pour stocker le certificat CA (doit être unique sur le modem) */
#define TLS_SEC_TAG 42

/* Certificat racine du serveur (à remplacer par le vôtre, voir le README) */
static const char ca_certificate[] =
"-----BEGIN CERTIFICATE-----\n"
"COLLEZ_ICI_LE_CERTIFICAT_RACINE_PEM_RECUPERE_AVEC_OPENSSL\n"
"-----END CERTIFICATE-----\n";

/* ------------------------------------- */

static int cert_provision(void)
{
	int err;
	bool exists;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				     MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				     &exists);
	if (err) {
		LOG_ERR("Erreur verification certificat existant: %d", err);
		return err;
	}

	if (exists) {
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					     MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			LOG_ERR("Erreur suppression ancien certificat: %d", err);
		}
	}

	LOG_INF("Ecriture du certificat CA dans le modem (sec_tag %d)...", TLS_SEC_TAG);
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    ca_certificate, strlen(ca_certificate));
	if (err) {
		LOG_ERR("Erreur ecriture certificat: %d", err);
	}

	return err;
}

static int modem_configure(void)
{
	int err;

	LOG_INF("Initialisation de la bibliotheque modem...");
	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("Echec init modem lib: %d", err);
		return err;
	}

	/* Le modem doit etre en mode hors-ligne (CFUN=4) pour ecrire un certificat */
	LOG_INF("Passage du modem en mode hors-ligne...");
	err = lte_lc_func_mode_set(LTE_LC_FUNC_MODE_OFFLINE);
	if (err) {
		LOG_ERR("Echec passage hors-ligne: %d", err);
		return err;
	}

	err = cert_provision();
	if (err) {
		return err;
	}

	LOG_INF("Connexion au reseau LTE-M via la carte eSIM iBasis...");
	err = lte_lc_connect();
	if (err) {
		LOG_ERR("Echec connexion LTE: %d", err);
		return err;
	}

	LOG_INF("Connecte au reseau LTE.");
	return 0;
}

/* Construit et envoie la requete HTTPS POST vers l'API SendGrid */
static int send_email(void)
{
	int err;
	int fd = -1;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res;
	char request[1024];
	char response[512];
	char body[512];
	sec_tag_t sec_tag_list[] = { TLS_SEC_TAG };

	/* Corps JSON attendu par l'API v3 SendGrid /mail/send */
	snprintf(body, sizeof(body),
		"{"
		"\"personalizations\":[{\"to\":[{\"email\":\"%s\"}]}],"
		"\"from\":{\"email\":\"%s\"},"
		"\"subject\":\"%s\","
		"\"content\":[{\"type\":\"text/plain\",\"value\":\"%s\"}]"
		"}",
		EMAIL_TO, EMAIL_FROM, EMAIL_SUBJECT, EMAIL_BODY);

	err = getaddrinfo(SENDGRID_HOST, SENDGRID_PORT, &hints, &res);
	if (err) {
		LOG_ERR("getaddrinfo() a echoue: %d", err);
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (fd < 0) {
		LOG_ERR("Echec creation socket TLS: %d", errno);
		freeaddrinfo(res);
		return -1;
	}

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
	if (err) {
		LOG_ERR("Echec configuration sec_tag: %d", errno);
		goto cleanup;
	}

	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, SENDGRID_HOST, strlen(SENDGRID_HOST));
	if (err) {
		LOG_ERR("Echec configuration TLS_HOSTNAME: %d", errno);
		goto cleanup;
	}

	int peer_verify = TLS_PEER_VERIFY_REQUIRED;
	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
	if (err) {
		LOG_ERR("Echec configuration TLS_PEER_VERIFY: %d", errno);
		goto cleanup;
	}

	LOG_INF("Connexion a %s...", SENDGRID_HOST);
	err = connect(fd, res->ai_addr, res->ai_addrlen);
	if (err) {
		LOG_ERR("Echec connexion TLS: %d", errno);
		goto cleanup;
	}

	snprintf(request, sizeof(request),
		"POST /v3/mail/send HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Authorization: Bearer %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		SENDGRID_HOST, SENDGRID_API_KEY, (int)strlen(body), body);

	LOG_INF("Envoi de la requete HTTPS (email)...");
	err = send(fd, request, strlen(request), 0);
	if (err < 0) {
		LOG_ERR("Echec envoi requete: %d", errno);
		goto cleanup;
	}

	memset(response, 0, sizeof(response));
	int received = recv(fd, response, sizeof(response) - 1, 0);
	if (received > 0) {
		LOG_INF("Reponse du serveur:\n%s", response);
	} else {
		LOG_WRN("Pas de reponse lue (received=%d, errno=%d)", received, errno);
	}

cleanup:
	freeaddrinfo(res);
	close(fd);
	return err;
}

int main(void)
{
	int err;

	LOG_INF("=== Thingy:91 - Envoi d'e-mail via LTE-M ===");

	err = modem_configure();
	if (err) {
		LOG_ERR("Configuration modem/LTE echouee, arret.");
		return 0;
	}

	err = send_email();
	if (err) {
		LOG_ERR("Echec envoi de l'email.");
	} else {
		LOG_INF("Requete d'envoi d'email terminee.");
	}

	/* Repasse le modem hors-ligne pour economiser les 10 Mo du forfait iBasis */
	lte_lc_func_mode_set(LTE_LC_FUNC_MODE_OFFLINE);

	return 0;
}