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

	return BGP_NLRI_PARSE_OK;
}

int bgp_rtc_filter(struct peer *peer, struct ecommunity *ecom, bool show_command)
{
	uint8_t sub_type = 0;
	struct prefix cmp;
	uint8_t *pnt;
	bool rt_found = false;
	char *ecom_str;
	bool debug = !show_command && BGP_DEBUG(update, UPDATE_OUT);

	/* Build prefix to compare with */
	cmp.family = AF_RTC;
	cmp.prefixlen = BGP_RTC_MAX_PREFIXLEN;
	cmp.u.prefix_rtc.origin_as = peer->as;

	for (uint32_t i = 0; i < ecom->size; i++) {
		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);

		sub_type = *++pnt;

		if (sub_type == ECOMMUNITY_ROUTE_TARGET) {
			rt_found = true;

			if (peer->rtc_plist == NULL) {
				if (debug) {
					ecom_str = ecommunity_ecom2str(ecom,
								       ECOMMUNITY_FORMAT_DISPLAY, 0);
					zlog_debug("Filtered a prefix with EC(%s) to peer %pBP because RTC prefix-list does not exist",
						   ecom_str, peer);
					XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
				}
				return true;
			}

			memcpy(&cmp.u.prefix_rtc.route_target, ecom->val + (i * ecom->unit_size),
			       ECOMMUNITY_SIZE);
			if (prefix_list_apply_ext(peer->rtc_plist, NULL, &cmp, true) ==
			    PREFIX_PERMIT)
				return false;
		}
	}

	if (!rt_found)
		return false;

	if (debug) {
		ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
		zlog_debug("Filtered a prefix with EC(%s) to peer %pBP because of RTC prefix-list",
			   ecom_str, peer);
		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	return true;
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

/* Adaption of bgp_static_update */
void bgp_rtc_add_dynamic(struct bgp *bgp, struct ecommunity_val *eval, uint32_t prefixlen)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;


	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);

	attr.nexthop.s_addr = INADDR_ANY;

	bgp_attr_set_med(&attr, 0);

	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;


	if (bgp_in_graceful_shutdown(bgp))
		bgp_attr_add_gshut_community(&attr);

	attr_new = bgp_attr_intern(&attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	if (pi) {
		bgp_attr_unintern(&attr_new);
		bgp_dest_unlock_node(dest);
		return;
	}
	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_new, dest);

	bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, &prefix, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, new, afi, safi);

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
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

void bgp_rtc_remove_dynamic(struct bgp *bgp, struct ecommunity_val *eval, uint32_t prefixlen)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;

	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	/* Check selected route and self inserted route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	/* Withdraw static BGP route from routing table. */
	if (pi) {
		SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
		bgp_aggregate_decrement(bgp, &prefix, pi, afi, safi);
		bgp_unlink_nexthop(pi);
		bgp_path_info_delete(dest, pi);
		bgp_process(bgp, dest, pi, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
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
