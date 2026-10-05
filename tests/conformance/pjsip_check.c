/* pjsip_check.c -- pjsip as the oracle for every SIP message the PBX emits.
 *
 * Reads a corpus of raw datagrams and reports, per message, whether pjsip
 * would accept it the way a pjsip phone's UDP transport does:
 *
 *   1. pjsip_parse_msg() returns a message AND its parse-error list is empty.
 *      pjsip_tpmgr_receive_packet() (sip_transport.c) drops the packet
 *      ("Dropping N bytes packet") on either.
 *   2. Call-ID (non-empty), From, To, Via and CSeq are all present. The same
 *      function drops the packet with PJSIP_EMISSINGHDR otherwise.
 *   3. A response's status code is 100..699 (PJSIP_EINVALIDSTATUS otherwise).
 *   4. An application/sdp body passes pjmedia_sdp_parse() and
 *      pjmedia_sdp_validate(); pjsua answers 400/488 to a body that doesn't.
 *
 * Corpus format (written by tests/conformance/emitted_conformance.py):
 *   repeated:  "<decimal byte length>\n" <exactly that many raw bytes>
 * Output: one line per message, "<index> OK" or "<index> FAIL <reason>".
 * Exit status: 0 when every message was read (failures are reported, not
 * judged -- the allowlist lives in the Python driver), 2 on a harness error.
 */
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjmedia/sdp.h>
#include <pjmedia/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pj_caching_pool g_cp;

static void check_one(pjsip_endpoint* endpt, int idx, char* buf, pj_size_t len)
{
	pj_pool_t* pool = pjsip_endpt_create_pool(endpt, "chk", 16000, 16000);
	pjsip_parser_err_report err_list;
	pjsip_msg* msg;
	char reason[512];
	reason[0] = '\0';

	pj_list_init(&err_list);
	msg = pjsip_parse_msg(pool, buf, len, &err_list);
	if (msg == NULL || !pj_list_empty(&err_list)) {
		pjsip_parser_err_report* e = err_list.next;
		int n = snprintf(reason, sizeof(reason), "parse%s", msg ? "" : " (no message)");
		while (e != &err_list && n < (int)sizeof(reason) - 1) {
			const int w = snprintf(reason + n, sizeof(reason) - (size_t)n,
				": %s parsing '%.*s' line %d col %d",
				pj_exception_id_name(e->except_code),
				(int)e->hname.slen, e->hname.ptr, e->line, e->col);
			if (w < 0) break;
			/* snprintf returns the length it WANTED; clamp so n never passes the buffer (CodeQL cpp/overflowing-snprintf). */
			n += w;
			if (n > (int)sizeof(reason) - 1) n = (int)sizeof(reason) - 1;
			e = e->next;
		}
	} else {
		const pjsip_cid_hdr* cid = (const pjsip_cid_hdr*)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL);
		if (!cid || cid->id.slen == 0 ||
			!pjsip_msg_find_hdr(msg, PJSIP_H_FROM, NULL) ||
			!pjsip_msg_find_hdr(msg, PJSIP_H_TO, NULL) ||
			!pjsip_msg_find_hdr(msg, PJSIP_H_VIA, NULL) ||
			!pjsip_msg_find_hdr(msg, PJSIP_H_CSEQ, NULL)) {
			snprintf(reason, sizeof(reason), "missing mandatory header (PJSIP_EMISSINGHDR)");
		} else if (msg->type == PJSIP_RESPONSE_MSG &&
			(msg->line.status.code < 100 || msg->line.status.code >= 700)) {
			snprintf(reason, sizeof(reason), "invalid status %d", msg->line.status.code);
		} else if (msg->body && msg->body->len > 0 &&
			pj_stricmp2(&msg->body->content_type.type, "application") == 0 &&
			pj_stricmp2(&msg->body->content_type.subtype, "sdp") == 0) {
			pjmedia_sdp_session* sdp = NULL;
			char* copy = (char*)pj_pool_alloc(pool, msg->body->len + 1);
			pj_status_t st;
			memcpy(copy, msg->body->data, msg->body->len);
			copy[msg->body->len] = '\0';
			st = pjmedia_sdp_parse(pool, copy, msg->body->len, &sdp);
			if (st == PJ_SUCCESS) st = pjmedia_sdp_validate(sdp);
			if (st != PJ_SUCCESS) {
				char eb[160];
				pjmedia_strerror(st, eb, sizeof(eb));
				snprintf(reason, sizeof(reason), "sdp: %s", eb);
			}
		}
	}
	if (reason[0]) printf("%d FAIL %s\n", idx, reason);
	else printf("%d OK\n", idx);
	pj_pool_release(pool);
}

int main(int argc, char** argv)
{
	pjsip_endpoint* endpt = NULL;
	FILE* f;
	int idx = 0;
	unsigned long len;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <corpus>\n", argv[0]);
		return 2;
	}
	pj_log_set_level(0);
	if (pj_init() != PJ_SUCCESS || pjlib_util_init() != PJ_SUCCESS) return 2;
	pj_caching_pool_init(&g_cp, &pj_pool_factory_default_policy, 0);
	if (pjsip_endpt_create(&g_cp.factory, "pjsip_check", &endpt) != PJ_SUCCESS) return 2;

	f = fopen(argv[1], "rb");
	if (!f) { perror(argv[1]); return 2; }
	while (fscanf(f, "%lu", &len) == 1) {
		char* buf;
		if (fgetc(f) != '\n' || len == 0 || len > PJSIP_MAX_PKT_LEN) {
			fprintf(stderr, "corrupt corpus at record %d\n", idx);
			return 2;
		}
		buf = (char*)malloc(len + 1);
		if (fread(buf, 1, len, f) != len) { fprintf(stderr, "short record %d\n", idx); return 2; }
		buf[len] = '\0';   /* pjsip's scanner requires a NUL-terminated buffer */
		check_one(endpt, idx++, buf, len);
		free(buf);
	}
	fclose(f);
	pjsip_endpt_destroy(endpt);
	pj_caching_pool_destroy(&g_cp);
	return 0;
}
