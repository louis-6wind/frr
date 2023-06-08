// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"
#include "bgpd/bgp_debug.h"

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	int psize = 0;

	/* Iterate over all received prefixes */
	for (; pnt < lim; pnt += psize) {
		struct prefix p = { 0 };

		p.prefixlen = *pnt++;
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
			if (prefix_bgp_rtc_set(peer->host, &p, PREFIX_PERMIT, 0))
				zlog_info("Withdrawn prefix %pFX is not in RTC prefix-list", &p);

			peer->rtc_plist = prefix_list_get(AFI_IP, 0, 1, peer->host);
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		} else {
			prefix_bgp_rtc_set(peer->host, &p, PREFIX_PERMIT, 1);
			peer->rtc_plist = prefix_list_get(AFI_IP, 0, 1, peer->host);
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
		}
	}

	bgp_announce_route(peer, AFI_L2VPN, SAFI_EVPN, false);

	return BGP_NLRI_PARSE_OK;
}

int bgp_rtc_filter(struct peer *peer, struct attr *attr, const struct prefix *p)
{
	struct ecommunity *ecom = bgp_attr_get_ecommunity(attr);
	uint8_t sub_type = 0;
	struct prefix cmp;
	uint8_t *pnt;

	if (ecom == NULL)
		return false;

	/* Build prefix to compare with */
	cmp.family = AF_RTC;
	cmp.prefixlen = BGP_RTC_MAX_PREFIXLEN;
	cmp.u.prefix_rtc.origin_as = peer->as;


	for (uint32_t i = 0; i < ecom->size; i++) {
		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);

		sub_type = *++pnt;

		if (sub_type == ECOMMUNITY_ROUTE_TARGET) {
			if (peer->rtc_plist == NULL) {
				if (BGP_DEBUG(update, UPDATE_OUT)) {
					zlog_debug("Filtered prefix %pFX because RTC prefix-list does not exist",
						   p);
				}
				return true;
			}

			memcpy(&cmp.u.prefix_rtc.route_target, ecom->val + (i * ecom->unit_size),
			       ECOMMUNITY_SIZE);
			if (prefix_list_apply_ext(peer->rtc_plist, NULL, &cmp, true) == PREFIX_DENY) {
				if (BGP_DEBUG(update, UPDATE_OUT)) {
					zlog_debug("Filtered prefix %pFX because of RTC prefix-list",
						   p);
				}
				return true;
			}
		}
	}
	return false;
}
