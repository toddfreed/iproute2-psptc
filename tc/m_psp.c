// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * m_psp.c		PSP encryption action
 */

#include <stdio.h>
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"
#include <linux/tc_act/tc_psp.h>

static void explain(void)
{
	fprintf(stderr,
		"Usage: psp encap assoc ASSOC_ID [mode MODE] [CONTROL] [index INDEX]\n"
		"       psp decap [mode MODE] [CONTROL] [index INDEX]\n"
		"where:\n"
		"\tASSOC_ID := ID of a Tx association, from PSP netlink assoc-add\n"
		"\tdecap takes no association: match the packets with flower\n"
		"\tpsp_spi, psp_ver and psp_dev\n"
		"\tMODE := transport (default) | tunnel\n"
		"\t        tunnel: encap takes the outer addresses from a\n"
		"\t        preceding \"tunnel_key set\", decap removes the outer\n"
		"\t        headers; hardware offload (skip_sw) only\n"
		"\tCONTROL := reclassify | pipe | drop | continue | pass |\n"
		"\t           goto chain <CHAIN_INDEX>\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int psp_set_action(__u32 *action, __u32 a)
{
	if (*action && *action != a) {
		fprintf(stderr, "psp: only one of \"encap\" and \"decap\"\n");
		return -1;
	}
	*action = a;
	return 0;
}

static int parse_psp(const struct action_util *a, int *argc_p, char ***argv_p,
		     int tca_id, struct nlmsghdr *n)
{
	struct tc_psp p = { 0 };
	bool assoc_set = false;
	__u32 action = 0;
	int mode = -1;
	char **argv = *argv_p;
	struct rtattr *tail;
	int argc = *argc_p;
	__u32 assoc;

	if (matches(*argv, "psp") != 0)
		return -1;
	NEXT_ARG();

	while (argc > 0) {
		if (matches(*argv, "encap") == 0) {
			if (psp_set_action(&action, TCA_PSP_ACT_ENCAP))
				return -1;
		} else if (matches(*argv, "decap") == 0) {
			if (psp_set_action(&action, TCA_PSP_ACT_DECAP))
				return -1;
		} else if (matches(*argv, "assoc") == 0) {
			NEXT_ARG();
			if (get_u32(&assoc, *argv, 0)) {
				fprintf(stderr, "psp: Illegal \"assoc\"\n");
				return -1;
			}
			assoc_set = true;
		} else if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "transport") == 0) {
				mode = TCA_PSP_MODE_TRANSPORT;
			} else if (strcmp(*argv, "tunnel") == 0) {
				mode = TCA_PSP_MODE_TUNNEL;
			} else {
				fprintf(stderr, "psp: Illegal \"mode\"\n");
				return -1;
			}
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
		NEXT_ARG_FWD();
	}

	parse_action_control_dflt(&argc, &argv, &p.action, false, TC_ACT_PIPE);

	if (argc && matches(*argv, "index") == 0) {
		NEXT_ARG();
		if (get_u32(&p.index, *argv, 10)) {
			fprintf(stderr, "psp: Illegal \"index\"\n");
			return -1;
		}
		NEXT_ARG_FWD();
	}

	if (!p.index) {
		if (!action) {
			fprintf(stderr, "psp: \"encap\" or \"decap\" required\n");
			usage();
		}
		if (action == TCA_PSP_ACT_ENCAP && !assoc_set) {
			fprintf(stderr, "psp: \"encap\" requires \"assoc\"\n");
			usage();
		}
	}

	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_PSP_PARMS, &p, sizeof(p));
	if (action)
		addattr32(n, MAX_MSG, TCA_PSP_ACTION, action);
	if (assoc_set)
		addattr32(n, MAX_MSG, TCA_PSP_ASSOC_ID, assoc);
	if (mode >= 0)
		addattr8(n, MAX_MSG, TCA_PSP_MODE, mode);
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_psp(const struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_PSP_MAX + 1];
	struct tc_psp *p;
	__u32 action = 0;

	print_string(PRINT_ANY, "kind", "%s ", "psp");
	if (!arg)
		return 0;

	parse_rtattr_nested(tb, TCA_PSP_MAX, arg);
	if (!tb[TCA_PSP_PARMS]) {
		fprintf(stderr, "Missing psp parameters\n");
		return -1;
	}
	p = RTA_DATA(tb[TCA_PSP_PARMS]);
	if (tb[TCA_PSP_ACTION])
		action = rta_getattr_u32(tb[TCA_PSP_ACTION]);

	switch (action) {
	case TCA_PSP_ACT_ENCAP:
		print_string(PRINT_ANY, "psp_action", "%s", "encap");
		break;
	case TCA_PSP_ACT_DECAP:
		print_string(PRINT_ANY, "psp_action", "%s", "decap");
		break;
	default:
		print_uint(PRINT_ANY, "psp_action", "action %u", action);
	}
	if (tb[TCA_PSP_ASSOC_ID])
		print_uint(PRINT_ANY, "assoc", " assoc %u",
			   rta_getattr_u32(tb[TCA_PSP_ASSOC_ID]));
	if (tb[TCA_PSP_MODE]) {
		__u8 mode = rta_getattr_u8(tb[TCA_PSP_MODE]);

		/* transport is the default: in JSON only */
		switch (mode) {
		case TCA_PSP_MODE_TRANSPORT:
			print_string(PRINT_JSON, "mode", NULL, "transport");
			break;
		case TCA_PSP_MODE_TUNNEL:
			print_string(PRINT_ANY, "mode", " mode %s", "tunnel");
			break;
		default:
			print_uint(PRINT_ANY, "mode", " mode %u", mode);
		}
	}

	print_action_control(" ", p->action, "");

	print_nl();
	print_uint(PRINT_ANY, "index", "\t index %u", p->index);
	print_int(PRINT_ANY, "ref", " ref %d", p->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", p->bindcnt);

	if (show_stats && tb[TCA_PSP_TM]) {
		struct tcf_t *tm = RTA_DATA(tb[TCA_PSP_TM]);

		print_tm(tm);
	}
	print_nl();
	return 0;
}

struct action_util psp_action_util = {
	.id = "psp",
	.parse_aopt = parse_psp,
	.print_aopt = print_psp,
};
