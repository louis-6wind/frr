// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	int psize = 0;

	/* Iterate over all received prefixes */
	for (; pnt < lim; pnt += psize) {
		struct prefix p = { 0 };

		p.prefixlen = *pnt++;
		/* TODO: Correctly handle prefixlen == 0 */
		if (p.prefixlen > BGP_RTC_MAX_PREFIXLEN || p.prefixlen < 32) {
			zlog_err("SAFI_RTC parse error. Invalid prefixlen: %u", p.prefixlen);
			return BGP_NLRI_PARSE_ERROR;
		}

		p.family = AF_RTC;
		psize = PSIZE(p.prefixlen);
		if (pnt + psize > lim) {
			zlog_err("SAFI_RTC parse error.");
			return BGP_NLRI_PARSE_ERROR;
		}

		/* Mask the value according to the prefixlen */
		for (int j = p.prefixlen; j < psize * 8; j++)
			pnt[j / 8] &= ~(1 << (j % 8));

		p.u.prefix_rtc.origin_as = ntohl(*(uint32_t *)pnt);

		memcpy(&p.u.prefix_rtc.route_target, pnt + 4, psize - 4);

		if (withdraw) {
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		} else {
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
		}
	}

	return BGP_NLRI_PARSE_OK;
}

static void bgp_rtc_add_static(struct bgp *bgp, struct ecommunity_val *eval, uint16_t prefixlen)
{
	/* TODO: Move prefix creation from eval into separate function and handle incorrect prefixlens */
	struct prefix prefix = { 0 };
	struct bgp_static *bgp_static;

	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	if (prefixlen >= 32) {
		memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);
	}

	bgp_static = bgp_static_new();
	bgp_static_update(bgp, &prefix, bgp_static, AFI_IP, SAFI_RTC);
}

/* Adaption of bgp_static_withdraw */
static void bgp_rtc_remove_static(struct bgp *bgp, struct ecommunity_val *eval, uint16_t prefixlen)
{
	struct prefix prefix = { 0 };
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);
	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], &prefix);

	if (!dest)
		return;

	bgp_static_withdraw(bgp, &prefix, AFI_IP, SAFI_RTC, NULL);

	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static)
		bgp_static_free(bgp_static);

	bgp_dest_set_bgp_static_info(dest, NULL);
	bgp_dest_unlock_node(dest);
}

int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add)
{
	struct ecommunity *ecom = NULL;
	int plen = BGP_RTC_MAX_PREFIXLEN;
	char *pnt;
	char *cp;

	/* Find slash inside string. */
	pnt = strchr(str, '/');

	/* String doesn't contain slash. */
	if (pnt == NULL) {
		ecom = ecommunity_str2com(str, ECOMMUNITY_ROUTE_TARGET, 0);
		if (ecom == NULL) {
			vty_out(vty, "%% Can't parse ecommunity %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		plen = (uint8_t)atoi(++pnt);
		cp = XMALLOC(MTYPE_TMP, (pnt - str) + 1);
		memcpy(cp, str, pnt - str - 1);
		*(cp + (pnt - str) - 1) = '\0';
		ecom = ecommunity_str2com(cp, ECOMMUNITY_ROUTE_TARGET, 0);

		XFREE(MTYPE_TMP, cp);

		if (ecom == NULL) {
			vty_out(vty, "%% Can't parse ecommunity %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Get prefix length. */
		if (plen != 0 && (plen < 32 || plen > BGP_RTC_MAX_PREFIXLEN)) {
			ecommunity_free(&ecom);
			vty_out(vty, "%% Invalid prefix length %d\n", plen);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (add)
		bgp_rtc_add_static(bgp, (struct ecommunity_val *)ecom->val, plen);
	else
		bgp_rtc_remove_static(bgp, (struct ecommunity_val *)ecom->val, plen);

	ecommunity_free(&ecom);

	return CMD_SUCCESS;
}

char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
			     const struct rtc_info *rtc_info)
{
	struct ecommunity *ecom;
	char *ecom_str;
	char *cbuf = buf;

	if (prefix_len == 96) {
		ecom = ecommunity_parse((uint8_t *)rtc_info->route_target, 8, true);
		ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);

		snprintfrr(buf, size, "%u:%s", rtc_info->origin_as, ecom_str);
		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	} else if (prefix_len == 32)
		snprintfrr(buf, size, "%u:RT:0", rtc_info->origin_as);
	else if (prefix_len == 0)
		snprintfrr(buf, size, "0:RT:0");
	else
		snprintfrr(buf, size, "UNK RTC Prefix");

	return cbuf;
}

void bgp_rtc_init(void)
{
	prefix_set_rtc_display_hook(bgp_rtc_prefix_display);
}
