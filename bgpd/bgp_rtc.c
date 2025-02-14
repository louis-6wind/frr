// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"
#include "bgpd/bgp_debug.h"

DEFINE_MTYPE(BGPD, BGP_RTC_PLIST, "BGP Route-Target Constraint prefix-list");
DEFINE_MTYPE(BGPD, BGP_RTC_PLIST_ENTRY, "BGP Route-Target Constraint prefix-list entry");
DEFINE_MTYPE(BGPD, BGP_RTC_PLIST_ENTRY_ASN, "BGP Route-Target Constraint prefix-list Origin AS");

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	char bgp_router_id_str[INET_ADDRSTRLEN];
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

		zlog_debug("%s: Received %s about %pFX from %pBP", __func__,
			   withdraw ? "withdraw" : "update", &p, peer);

		if (withdraw || peer->as == peer->bgp->as) {
			/* (Un)set prefix-list for internal peers.
			 * Prefixes from external peers are added if needed into prefix-list
			 * after best path computation */
			snprintfrr(bgp_router_id_str, sizeof(bgp_router_id_str), "%pI4",
				   &peer->remote_id);
			if (bgp_rtc_plist_entry_set(peer, &p, !withdraw)) {
				/* only set update flags if the peer prefix-list has changed */
				SET_FLAG(peer->flags, PEER_FLAG_RTC_UPDATE);
				zlog_debug("DEBFLAG %pBP set PEER_FLAG_RTC_UPDATE %s", peer,
					   __func__);
				zlog_debug("%s: %s %pFX - request %pBP refresh DEB", __func__,
					   withdraw ? "withdraw" : "update", &p, peer);
			}
		}

		if (withdraw)
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		else
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
	}

	return BGP_NLRI_PARSE_OK;
}

/* Check whether a route-target match the RTC prefix-list
 *
 * If previous_state is true, it returns the previous matching state before the RTC
 * prefix-list was updated.
 */
static enum rtc_prefix_list_type bgp_rtc_plist_entry_match(struct bgp_rtc_plist *rtc_plist,
							   uint8_t *route_target,
							   bool previous_state)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	struct listnode *node;
	size_t byte_count;
	size_t extra_bits;
	uint8_t mask;

	for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, node, rtc_pentry)) {
		if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_NEW) && previous_state)
			continue;
		if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE) && !previous_state)
			continue;
		if (rtc_pentry->prefixlen == 0 || rtc_pentry->prefixlen == 32)
			return RTC_PREFIX_PERMIT;
		if (rtc_pentry->prefixlen == 96) {
			if (!memcmp(rtc_pentry->route_target, route_target,
				    sizeof(rtc_pentry->route_target)))
				return RTC_PREFIX_PERMIT;
			continue;
		}
		byte_count = rtc_pentry->prefixlen / 8 - sizeof(as_t);
		if (memcmp(rtc_pentry->route_target, route_target, byte_count))
			continue;

		extra_bits = rtc_pentry->prefixlen % 8;
		if (!extra_bits)
			return RTC_PREFIX_PERMIT;

		mask = (1U << extra_bits) - 1;
		if ((rtc_pentry->route_target[byte_count] & mask) ==
		    (route_target[byte_count] & mask))
			return RTC_PREFIX_PERMIT;
	}

	return RTC_PREFIX_DENY;
}

/* Return whether route-target constraint must filter an advertisement via 'peer' based on the
 * route-target attributes contained in the 'ecom' extended community list.
 *
 * prefix 'p' argument is optional. If set, it enables logging when "debug bgp update out" is on.
 * Its value is displayed in the logs.
 *
 * If previous_state is true, it returns the previous filtering state before the RTC
 * prefix-list was updated.
 */
enum rtc_prefix_list_type bgp_rtc_filter(struct peer *peer, struct ecommunity *ecom,
					 struct prefix *p, bool previous_state)
{
	uint8_t sub_type = 0;
	uint8_t *pnt;
	bool rt_found = false;
	char *ecom_str;
	bool debug = p && BGP_DEBUG(update, UPDATE_OUT);
	struct bgp_rtc_plist *rtc_plist = bgp_peer_get_rtc_plist(peer);

	if (!rtc_plist) {
		if (debug) {
			ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
			zlog_debug("%sAccepted %pFX with EC(%s) to peer %pBP because RTC prefix-list does not exist",
				   previous_state ? "previous_state: " : "", p, ecom_str, peer);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
		return RTC_PREFIX_PERMIT;
	}

	if (previous_state &&
	    ((p->family == AF_INET && CHECK_FLAG(rtc_plist->flags, RTC_PLIST_NEW_IPV4_VPN)) ||
	     (p->family == AF_INET6 && CHECK_FLAG(rtc_plist->flags, RTC_PLIST_NEW_IPV6_VPN)) ||
	     (p->family == AF_ETHERNET && CHECK_FLAG(rtc_plist->flags, RTC_PLIST_NEW_EVPN))))
		return RTC_PREFIX_UNDEF;

	for (uint32_t i = 0; i < ecom->size; i++) {
		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);
		sub_type = *(pnt + 1);

		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		rt_found = true;
		if (bgp_rtc_plist_entry_match(rtc_plist, pnt, previous_state) == RTC_PREFIX_DENY)
			continue;

		if (debug) {
			ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
			zlog_debug("%sAccepted %pFX with EC(%s) to peer %pBP because of RTC prefix-list",
				   previous_state ? "previous_state: " : "", p, ecom_str, peer);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}

		return RTC_PREFIX_PERMIT;
	}

	if (!rt_found)
		/* No Route-target found => No filtering */
		return RTC_PREFIX_PERMIT;

	if (debug) {
		ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
		zlog_debug("%sFiltered %pFX with EC(%s) to peer %pBP because of RTC prefix-list",
			   previous_state ? "previous_state: " : "", p, ecom_str, peer);
		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	return RTC_PREFIX_DENY;
}

static void bgp_rtc_add_static(struct bgp *bgp, struct ecommunity_val *eval, uint16_t prefixlen)
{
	/* TODO: Move prefix creation from eval into separate function and handle incorrect prefixlens */
	struct prefix prefix = { 0 };
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	if (prefixlen >= 32)
		memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);

	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], &prefix);
	bgp_static = bgp_dest_get_bgp_static_info(dest);

	if (bgp_static) {
		bgp_dest_unlock_node(dest);
		return;
	}

	bgp_static = bgp_static_new();
	bgp_static->label = MPLS_INVALID_LABEL;
	bgp_static->label_index = BGP_INVALID_LABEL_INDEX;

	bgp_dest_set_bgp_static_info(dest, bgp_static);

	bgp_static->valid = 1;
	bgp_static_update(bgp, &prefix, bgp_static, AFI_IP, SAFI_RTC);
}

/* Adaption of bgp_static_update */
void bgp_rtc_add_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = BGP_RTC_MAX_PREFIXLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(BGP_RTC_MAX_PREFIXLEN) - 4);
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
	if (prefixlen >= 32)
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

void bgp_rtc_remove_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = BGP_RTC_MAX_PREFIXLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(BGP_RTC_MAX_PREFIXLEN) - 4);

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

void bgp_rtc_update_vpn_policy_ecommunity_dynamic(struct bgp *bgp, afi_t afi,
						  struct ecommunity *old_ecom,
						  struct ecommunity *new_ecom)
{
	afi_t afi_iter;
	uint8_t *pnt, *pnt_iter;
	uint32_t i, j;
	struct bgp *bgp_iter;
	struct listnode *node;
	struct ecommunity *ecom_iter;
	bool rt_used;

	if (!bgp_get_default())
		return;

	if (old_ecom) {
		/* Withdraw the previous values that are not present:
		 * - in the new values
		 * - in any other BGP instance
		 */
		for (i = 0, pnt = old_ecom->val; i < old_ecom->size;
		     pnt += old_ecom->unit_size, i++) {
			if (new_ecom) {
				/* Check if the value if present in the new set */
				rt_used = false;
				for (j = 0, pnt_iter = new_ecom->val; j < new_ecom->size;
				     pnt_iter += new_ecom->unit_size, j++) {
					if (!memcmp(pnt_iter, pnt, new_ecom->unit_size)) {
						rt_used = true;
						break;
					}
				}

				if (rt_used)
					continue;
			}

			/* Check if the value if present in any other BGP instance */
			rt_used = false;
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_iter)) {
				for (afi_iter = AFI_IP; afi_iter <= AFI_IP6; ++afi_iter) {
					if (bgp_iter == bgp && afi_iter == afi)
						continue;
					ecom_iter = bgp_iter->vpn_policy[afi_iter]
							    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN];
					if (!ecom_iter)
						continue;
					for (j = 0, pnt_iter = ecom_iter->val; j < ecom_iter->size;
					     pnt_iter += ecom_iter->unit_size, j++) {
						if (!memcmp(pnt_iter, pnt, ecom_iter->unit_size)) {
							rt_used = true;
							break;
						}
					}
				}
			}
			if (!rt_used)
				bgp_rtc_remove_ecommunity_val_dynamic(bgp_get_default(),
								      (struct ecommunity_val *)pnt);
		}
	}

	if (new_ecom) {
		/* Add new RT values */
		for (i = 0, pnt = new_ecom->val; i < new_ecom->size; pnt += new_ecom->unit_size, i++)
			bgp_rtc_add_ecommunity_val_dynamic(bgp_get_default(),
							   (struct ecommunity_val *)pnt);
	}
}

int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add)
{
	struct ecommunity *ecom = NULL;
	int plen = BGP_RTC_MAX_PREFIXLEN;
	char *slash_pnt, *rt_pnt;
	char *cp;
	char *endptr;

	/* Find slash inside string. */
	slash_pnt = strchr(str, '/');
	rt_pnt = strstr(str, ":RT:");
	if (!rt_pnt)
		rt_pnt = strstr(str, ":rt:");

	/* String doesn't contain slash. */
	if (slash_pnt == NULL && rt_pnt == NULL) {
		ecom = ecommunity_str2com(str, ECOMMUNITY_ROUTE_TARGET, 0);
		if (ecom == NULL) {
			vty_out(vty, "%% Can't parse ecommunity %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (slash_pnt) {
		plen = (uint8_t)strtol(++slash_pnt, &endptr, 10);

		/* If endptr == pnt, no digits were found; also check for leftover chars.
         * Check prefix length
         */
		if (endptr == slash_pnt || *endptr != '\0') {
			vty_out(vty, "%% Invalid prefix length %s \n", slash_pnt);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (endptr == slash_pnt || *endptr != '\0') {
			vty_out(vty, "%% Invalid prefix length %s \n", slash_pnt);
			return CMD_WARNING_CONFIG_FAILED;
		}
			||
		    !(plen >= 0 && plen <= 32 && rt_pnt) || (plenplen > BGP_RTC_MAX_PREFIXLEN))) {


		if (rt_pnt)
			/* extract origin AS */

		cp = XSTRDUP(MTYPE_TMP, str);
		cp[(slash_pnt - str) - 1] = '\0';
		ecom = ecommunity_str2com(cp, ECOMMUNITY_ROUTE_TARGET, 0);
		XFREE(MTYPE_TMP, cp);

		if (ecom == NULL) {
			vty_out(vty, "%% Can't parse ecommunity %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else
		return CMD_WARNING_CONFIG_FAILED;

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
	char *cbuf = buf;

	if (prefix_len > 32 && prefix_len <= 96)
		snprintfrr(buf, size, "%u:%s", rtc_info->origin_as,
			   ecommunity_rt_str(rtc_info->route_target));
	else if (prefix_len > 0 && prefix_len <= 32)
		snprintfrr(buf, size, "%u:RT:0", rtc_info->origin_as);
	else if (prefix_len == 0)
		snprintfrr(buf, size, "0:RT:0");
	else
		snprintfrr(buf, size, "UNK RTC Prefix");

	return cbuf;
}

static as_t *bgp_rtc_plist_entry_asn_new(void)
{
	return XCALLOC(MTYPE_BGP_RTC_PLIST_ENTRY_ASN, sizeof(as_t));
}

static void bgp_rtc_plist_entry_asn_free(void *arg)
{
	as_t *origin_as = arg;
	XFREE(MTYPE_BGP_RTC_PLIST_ENTRY_ASN, origin_as);
}

static struct bgp_rtc_plist_entry *bgp_rtc_plist_entry_new(void)
{
	struct bgp_rtc_plist_entry *rtc_pentry;

	rtc_pentry = XCALLOC(MTYPE_BGP_RTC_PLIST_ENTRY, sizeof(struct bgp_rtc_plist_entry));
	rtc_pentry->origin_as = list_new();
	rtc_pentry->origin_as->del = bgp_rtc_plist_entry_asn_free;

	return rtc_pentry;
}

static void bgp_rtc_plist_entry_free(void *args)
{
	struct bgp_rtc_plist_entry *rtc_pentry = args;
	list_delete(&rtc_pentry->origin_as);

	XFREE(MTYPE_BGP_RTC_PLIST_ENTRY, rtc_pentry);
}

static struct bgp_rtc_plist *bgp_rtc_plist_new(void)
{
	struct bgp_rtc_plist *rtc_plist;

	rtc_plist = XCALLOC(MTYPE_BGP_RTC_PLIST, sizeof(struct bgp_rtc_plist));
	rtc_plist->entries = list_new();
	rtc_plist->entries->del = bgp_rtc_plist_entry_free;

	return rtc_plist;
}

void bgp_rtc_plist_free(void *arg)
{
	struct bgp_rtc_plist *rtc_plist = arg;

	list_delete(&rtc_plist->entries);

	XFREE(MTYPE_BGP_RTC_PLIST, rtc_plist);
}

/* Add a RTC prefix p into rtc_plist RTC prefix-list
 *
 * Return 0 if the entry was already present and nothing has been done.
 * Return 1 instead if the entry was added.
 */
static int bgp_rtc_plist_entry_add(struct bgp_rtc_plist *rtc_plist, struct prefix *p)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	as_t *origin_as = NULL;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, node, rtc_pentry)) {
		if (memcmp(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
			    sizeof(rtc_pentry->route_target)))
			continue;
		if (rtc_pentry->prefixlen == p->prefixlen)
			break;
	}

	if (rtc_pentry) {
		zlog_debug("DEBFLAG change %s rtc_pentry->flags from %u to %u (unset remove) %s",
			   ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->flags,
			   rtc_pentry->flags & ~RTC_PLIST_ENTRY_REMOVE, __func__);
		UNSET_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE);
		if (list_isempty(rtc_pentry->origin_as))
			SET_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_NEW);
	} else {
		rtc_pentry = bgp_rtc_plist_entry_new();
		memcpy(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
		       sizeof(rtc_pentry->route_target));
		rtc_pentry->prefixlen = p->prefixlen;
		SET_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_NEW);
		zlog_debug("DEBFLAG change %s rtc_pentry->flags from 0 to %u %s",
			   ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->flags, __func__);
		origin_as = bgp_rtc_plist_entry_asn_new();
		*origin_as = p->u.prefix_rtc.origin_as;

		listnode_add(rtc_pentry->origin_as, origin_as);
		listnode_add(rtc_plist->entries, rtc_pentry);

		return 1;
	}

	for (ALL_LIST_ELEMENTS_RO(rtc_pentry->origin_as, node, origin_as)) {
		if (*origin_as == p->u.prefix_rtc.origin_as)
			break;
	}

	if (!origin_as) {
		origin_as = bgp_rtc_plist_entry_asn_new();
		*origin_as = p->u.prefix_rtc.origin_as;

		listnode_add(rtc_pentry->origin_as, origin_as);

		return 1;
	}

	return 0;
}

/* Delete a RTC prefix p from rtc_plist RTC prefix-list
 *
 * Return 0 if no entry was found.
 * Return 1 instead if an entry was actually removed.
 */
static int bgp_rtc_plist_entry_del(struct bgp_rtc_plist *rtc_plist, struct prefix *p)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	struct listnode *enode, *nenode, *asnode, *nasnode;
	as_t *origin_as = NULL;
	int ret = 0;

	for (ALL_LIST_ELEMENTS(rtc_plist->entries, enode, nenode, rtc_pentry)) {
		if (memcmp(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
			   sizeof(rtc_pentry->route_target)))
			continue;
		if (rtc_pentry->prefixlen != p->prefixlen)
			continue;
		for (ALL_LIST_ELEMENTS(rtc_pentry->origin_as, asnode, nasnode, origin_as)) {
			if (*origin_as != p->u.prefix_rtc.origin_as)
				continue;
			listnode_delete(rtc_pentry->origin_as, origin_as);
			bgp_rtc_plist_entry_asn_free(origin_as);
			ret = 1;
			break;
		}
		if (!list_isempty(rtc_pentry->origin_as))
			/* If origin AS list is not empty, the entry is still valid.
			 * Do not set Remove flag.
			 */
			break;

		zlog_debug("DEBFLAG change %s rtc_pentry->flags from %u to %u %s",
			   ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->flags,
			   RTC_PLIST_ENTRY_REMOVE, __func__);
		rtc_pentry->flags = RTC_PLIST_ENTRY_REMOVE;

		break;
	}

	return ret;
}

void bgp_peer_rtc_plist_reset_flags(struct peer *peer, afi_t afi, bool reset_entries)
{
	struct bgp_rtc_plist_entry *rtc_pentry;
	struct listnode *node, *nnode;

	if (!peer->rtc_plist)
		return;

	uint8_t old_flags = peer->rtc_plist->flags;

	if (afi == AFI_IP)
		UNSET_FLAG(peer->rtc_plist->flags, RTC_PLIST_NEW_IPV4_VPN);
	else if (afi == AFI_IP6)
		UNSET_FLAG(peer->rtc_plist->flags, RTC_PLIST_NEW_IPV6_VPN);
	else if (afi == AFI_L2VPN)
		UNSET_FLAG(peer->rtc_plist->flags, RTC_PLIST_NEW_EVPN);

	zlog_debug("DEBFLAG change %pBP rtc_plist->flags from %u to %u %s", peer, old_flags,
		   peer->rtc_plist->flags, __func__);

	if (!reset_entries)
		return;

	for (ALL_LIST_ELEMENTS(peer->rtc_plist->entries, node, nnode, rtc_pentry)) {
		if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE)) {
			listnode_delete(peer->rtc_plist->entries, rtc_pentry);
			bgp_rtc_plist_entry_free(rtc_pentry);
			continue;
		}
		zlog_debug("DEBFLAG change %s rtc_pentry->flags from %u to 0 %s",
			   ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->flags, __func__);
		RESET_FLAG(rtc_pentry->flags);
	}
}

static void bgp_peer_init_rtc_plist(struct peer *peer)
{
	peer->rtc_plist = bgp_rtc_plist_new();
	peer->rtc_plist->router_id.s_addr = peer->remote_id.s_addr;
	SET_FLAG(peer->rtc_plist->flags,
		 RTC_PLIST_NEW_IPV4_VPN | RTC_PLIST_NEW_IPV6_VPN | RTC_PLIST_NEW_EVPN);
	zlog_debug("DEBFLAG change %pBP rtc_plist->flags from 0 to %u %s", peer,
		   peer->rtc_plist->flags, __func__);
	listnode_add(peer->bgp->rtc_plists, peer->rtc_plist);
}

void bgp_peer_init_afi_rtc_plist(struct peer *peer, afi_t afi)
{
	struct bgp_rtc_plist *rtc_plist = bgp_peer_get_rtc_plist(peer);

	if (!rtc_plist)
		return;

	if (afi == AFI_IP) {
		zlog_debug("DEBFLAG change %pBP rtc_plist->flags from %u to %u %s", peer,
			   rtc_plist->flags, rtc_plist->flags & RTC_PLIST_NEW_IPV4_VPN, __func__);
		SET_FLAG(rtc_plist->flags, RTC_PLIST_NEW_IPV4_VPN);
	} else if (afi == AFI_IP6) {
		zlog_debug("DEBFLAG change %pBP rtc_plist->flags from %u to %u %s", peer,
			   rtc_plist->flags, rtc_plist->flags & RTC_PLIST_NEW_IPV6_VPN, __func__);
		SET_FLAG(rtc_plist->flags, RTC_PLIST_NEW_IPV6_VPN);
	} else if (afi == AFI_L2VPN) {
		zlog_debug("DEBFLAG change %pBP rtc_plist->flags from %u to %u %s", peer,
			   rtc_plist->flags, rtc_plist->flags & RTC_PLIST_NEW_EVPN, __func__);
		SET_FLAG(rtc_plist->flags, RTC_PLIST_NEW_EVPN);
	}
}

struct bgp_rtc_plist *bgp_peer_get_rtc_plist(struct peer *peer)
{
	struct bgp_rtc_plist *rtc_plist = NULL;
	struct listnode *node;

	if (peer->rtc_plist)
		return peer->rtc_plist;

	if (!peer->remote_id.s_addr)
		return NULL;

	if (peer->afc_nego[AFI_IP][SAFI_RTC]) {
		bgp_peer_init_rtc_plist(peer);

		return peer->rtc_plist;
	}

	for (ALL_LIST_ELEMENTS_RO(peer->bgp->rtc_plists, node, rtc_plist)) {
		if (!IPV4_ADDR_CMP(&rtc_plist->router_id, &peer->remote_id))
			return rtc_plist;
	}

	return NULL;
}

int bgp_rtc_plist_entry_set(struct peer *peer, struct prefix *p, bool add)
{
	if (!peer->rtc_plist)
		bgp_peer_init_rtc_plist(peer);

	if (add)
		return bgp_rtc_plist_entry_add(peer->rtc_plist, p);

	return bgp_rtc_plist_entry_del(peer->rtc_plist, p);
}

void bgp_show_rtc_plist(struct vty *vty, struct bgp_rtc_plist *rtc_plist, bool uj)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	json_object *json, *json_rtc_plist, *json_rt, *json_as_array;
	char bgp_router_id_str[INET_ADDRSTRLEN];
	struct listnode *enode, *asnode;
	as_t *origin_as = NULL;
	int64_t count = 0;

	snprintfrr(bgp_router_id_str, sizeof(bgp_router_id_str), "%pI4", &rtc_plist->router_id);

	if (uj) {
		json = json_object_new_object();
		json_rtc_plist = json_object_new_object();

		json_object_object_add(json, "rtcPrefixList", json_rtc_plist);

		json_object_string_add(json_rtc_plist, "prefixListName", bgp_router_id_str);

		for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, enode, rtc_pentry)) {
			if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE))
				continue;
			count++;
			json_rt = json_object_new_object();
			json_object_object_addf(json_rtc_plist, json_rt, "%s/%u", ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->prefixlen);

			json_as_array = json_object_new_array();
			json_object_object_add(json_rt, "originAS", json_as_array);
			for (ALL_LIST_ELEMENTS_RO(rtc_pentry->origin_as, asnode, origin_as))
				/* Display a string and not an integer to support AS dot notation in the future */
				json_array_string_addf(json_as_array, "%u", *origin_as);
		}

		json_object_int_add(json_rtc_plist, "prefixListCounter", count);

		vty_json(vty, json);

		return;
	}

	for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, enode, rtc_pentry)) {
		if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE))
			continue;
		count++;
	}

	vty_out(vty, "RTC prefix-list for peer router-ID %s: %lld entries\n", bgp_router_id_str,
		count);

	for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, enode, rtc_pentry)) {
		if (CHECK_FLAG(rtc_pentry->flags, RTC_PLIST_ENTRY_REMOVE))
			continue;
		vty_out(vty, "   %s/%u from origin ASNs:\n", ecommunity_rt_str(rtc_pentry->route_target), rtc_pentry->prefixlen);
		for (ALL_LIST_ELEMENTS_RO(rtc_pentry->origin_as, asnode, origin_as))
			vty_out(vty, "      %u\n", *origin_as);
	}
}

void bgp_rtc_init(void)
{
	prefix_set_rtc_display_hook(bgp_rtc_prefix_display);
}
