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
