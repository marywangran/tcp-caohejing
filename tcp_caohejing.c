// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <net/tcp.h>
#include <linux/win_minmax.h>

#define CAL_SCALE 8
#define CAL_UNIT (1 << CAL_SCALE)

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define UP 0
#define DOWN 1

static int debug = 1;
module_param(debug, int, 0644);

static int conservation = 1;
module_param(conservation, int, 0644);

struct caohejing {
	u32    rtt;
	u32    gain;
	u32    min_rtt_us;
	u32    rtt_cnt;
	u32    next_rtt_delivered;
	u32    prior_cwnd;
	struct minmax bw;
	u64    curr_bw;
	u64    last_bw;
	u64    cycle_mstamp;
	u32    prev_ca_state:3,
	       state:3,
	       packet_conservation:1;
};

static void tcp_caohejing_init(struct sock *sk)
{
	struct caohejing *w = inet_csk_ca(sk);

	w->gain = CAL_UNIT * 5 / 4;
	w->state = UP;
	w->min_rtt_us = 0x7fffffff;
	w->prev_ca_state = TCP_CA_Open;
	w->packet_conservation = 0;
	w->rtt_cnt = 0;
	w->curr_bw = 0;
	w->last_bw = 0;
	w->prior_cwnd = 0;

	minmax_reset(&w->bw, w->rtt_cnt, 0);
	w->next_rtt_delivered = 0;
	w->cycle_mstamp = 0;
}

static void tcp_caohejing_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (new_state == TCP_CA_Loss) {
		tp->snd_cwnd = tcp_packets_in_flight(tp) + 1;
	}
}

static u32 tcp_caohejing_undo_cwnd(struct sock *sk)
{
	struct caohejing *w = inet_csk_ca(sk);
	
	return max_t(u32, 2, w->prior_cwnd);
}

static u32 tcp_caohejing_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct caohejing *w = inet_csk_ca(sk);

	w->prior_cwnd = tp->snd_cwnd;
	return tcp_sk(sk)->snd_ssthresh;
}

static bool is_next_cycle_phase(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct caohejing *w = inet_csk_ca(sk);
	bool is_full_length = tcp_stamp_us_delta(tp->delivered_mstamp, w->cycle_mstamp) > w->min_rtt_us;

	if (w->cycle_mstamp == 0 || is_full_length) {
		w->cycle_mstamp = tp->delivered_mstamp;
		w->last_bw = w->curr_bw;
		w->curr_bw = minmax_get(&w->bw);
		return true;
	}
	return false;
}

static u64 caohejing_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;
	rate *= gain;
	rate >>= CAL_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - 1);
	return rate >> BW_SCALE;
}

static unsigned long caohejing_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = caohejing_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

static void caohejing_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	unsigned long rate = caohejing_bw_to_pacing_rate(sk, bw, gain);
	sk->sk_pacing_rate = rate;
}

static const int caohejing_min_tso_rate = 1200000;
static u32 caohejing_min_tso_segs(struct sock *sk)
{
	return sk->sk_pacing_rate < (caohejing_min_tso_rate >> 3) ? 1 : 2;
}

static u32 caohejing_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 segs, bytes;

	bytes = min_t(unsigned long, sk->sk_pacing_rate >> sk->sk_pacing_shift, GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);
	segs = max_t(u32, bytes / tp->mss_cache, caohejing_min_tso_segs(sk));

	return min(segs, 0x7FU);
}

static void tcp_caohejing_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct caohejing *w = inet_csk_ca(sk);
	u8 prev_ca_state = w->prev_ca_state, ca_state = inet_csk(sk)->icsk_ca_state;
	u64 bw, bdp;
	u32 cwnd, old_cwnd = tp->snd_cwnd;
	bool is_next = false;
	static int start = 0;

	if (!before(rs->prior_delivered, w->next_rtt_delivered)) {
		w->next_rtt_delivered = tp->delivered;
		w->rtt_cnt++;
	}

	if (rs->rtt_us > 0 && rs->rtt_us <= w->min_rtt_us)
		w->min_rtt_us = rs->rtt_us;

	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);
	if (bw > minmax_get(&w->bw)) {
		minmax_running_max(&w->bw, 10, w->rtt_cnt, bw);
		w->curr_bw = minmax_get(&w->bw);
	}

	is_next = is_next_cycle_phase(sk, rs);
	bw = minmax_get(&w->bw);

	if (start > 3) {
		switch (w->state) {
		case UP:
			if (20*bw > 21*w->last_bw) {
				w->gain = CAL_UNIT * 5 / 4;
			} else {
				w->gain = CAL_UNIT * 3 / 4;
				w->state = DOWN;
			}
			break;
		case DOWN:
			if (19*w->last_bw > 20*bw) {
				w->gain = CAL_UNIT * 5 / 4;
				w->state = UP;
			} else {
				w->gain = CAL_UNIT * 3 / 4;
			}
			break;

		default:
			break;
		}
	}
	start ++;
	bdp = (u64)bw * w->min_rtt_us;
	cwnd = max_t(u32, 2, (((bdp * CAL_UNIT) >> CAL_SCALE) + BW_UNIT - 1) / BW_UNIT);
	cwnd += 3 * caohejing_tso_segs_goal(sk);
	cwnd = (cwnd + 1) & ~1U;
	tp->snd_cwnd = cwnd;
	cwnd = old_cwnd;

	if (is_next) {
		w->rtt_cnt = 0;
		minmax_reset(&w->bw, w->rtt_cnt, 0);
	}

	if (conservation == 0)
		goto done;

	if (rs->losses > 0) {
		cwnd = max_t(s32, cwnd - rs->losses, 1);
	}
	if (ca_state == TCP_CA_Recovery && prev_ca_state != TCP_CA_Recovery) {
		cwnd = tcp_packets_in_flight(tp) + rs->acked_sacked;
		w->next_rtt_delivered = tp->delivered;
		w->packet_conservation = 1;
	} else if (prev_ca_state >= TCP_CA_Recovery && ca_state < TCP_CA_Recovery){
		tp->snd_cwnd = max(w->prior_cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
		w->state = UP;
		w->gain = CAL_UNIT * 5 / 4;
		w->packet_conservation = 0;
	}

	if (w->packet_conservation == 1) {
		w->state = DOWN;
		w->gain = CAL_UNIT * 3 / 4;
		tp->snd_cwnd = max_t(u32, cwnd, tcp_packets_in_flight(tp) + rs->acked_sacked);
	}

done:
	w->prev_ca_state = ca_state;
	caohejing_set_pacing_rate(sk, bw, w->gain);
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);

	if (debug)
		printk("##st:%d ca_st:%d bw:%llu last_bw:%llu cwnd:%d minrtt:%d gain:%d\n", w->state, ca_state, bw, w->last_bw, tp->snd_cwnd, w->min_rtt_us, w->gain);
}

static struct tcp_congestion_ops tcp_caohejing __read_mostly = {
	.init		= tcp_caohejing_init,
	.ssthresh	= tcp_caohejing_ssthresh,
	.cong_control   = tcp_caohejing_cong_control,
	.undo_cwnd      = tcp_caohejing_undo_cwnd,
	.set_state	= tcp_caohejing_state,
	.owner		= THIS_MODULE,
	.name		= "caohejing"
};

static int __init tcp_caohejing_register(void)
{
	BUILD_BUG_ON(sizeof(struct caohejing) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_caohejing);
}

static void __exit tcp_caohejing_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_caohejing);
}

module_init(tcp_caohejing_register);
module_exit(tcp_caohejing_unregister);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Caohejing");
