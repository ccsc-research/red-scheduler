/*
 *      MPTCP RED Scheduler
 *
 *      This scheduler sends all packets redundantly on all disjointed
 *      available subflows.
 *
 *      Initial Design & Implementation:
 *      Igor Steuck <islopes@inf.ufpr.br>
 *      Benevid Felix <benevid@inf.ufpr.br>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/semaphore.h>
#include <linux/types.h>
#include <linux/sort.h>
#include <net/mptcp.h>

#define MAX_T 2
#define MAX_SUBFLOWS 32
#define MIN_RTT 50
#define THRESHOLD(x) ((x <= 800) && ( x >= -800) ? 1:0)

/* Struct to store the data of a single subflow */
struct corrsched_sock_data {
    /* The skb or NULL */
    struct sk_buff *skb;
    /* End sequence number of the skb. This number should be checked
     * to be valid before the skb field is used
     */
    u32 skb_end_seq;
};

/* Struct to store the data of the control block */
struct corrsched_cb_data {
    /* The next subflow where a skb should be sent or NULL */
    struct tcp_sock *next_subflow;
};

/* This structure is used to save RTTs from a previous and a current
 * time frame */
struct sbflw_rtt{
    struct sbflw_rtt *next;
    u32 srtt;
    u32 r;
}__attribute__((packed));

struct sbflw_rtt_head{
    struct sbflw_rtt *next;
    struct sbflw_rtt *previous;
    u32 qlen;
    struct semaphore sem;
}__attribute__((packed));;

/* This structure stores a list of all subflows and their related info */
struct sbflw_queue{;
    struct sbflw_rtt_head *test_head;
    unsigned int cap;
    unsigned int cng; 
    unsigned int all_zero;
    u32 loc_id;
    s64 *corr;
    s64 corr_value;
    u8 path_index;
}__attribute__((packed));;

/* used in sorting */
struct sort_value{
    s64 value;
    unsigned int index;
}__attribute__((packed));

/* global clock to calculate the rtt capture time */
unsigned long cap_t = 0;

/* stores captured rtts and correlation values */
static struct sbflw_queue *sbflows = NULL;

/* list of least correlated paths */
static struct sort_value least_corr[MAX_SUBFLOWS];

/* stores, by index, the correlation values betweeen subflows */
s64 loc_id[MAX_SUBFLOWS][MAX_SUBFLOWS];

/* add an element to the queue */
static void queue_add(unsigned int n,
                unsigned int i){
    struct sbflw_rtt *last, *new;

    new = kmalloc(sizeof(new), GFP_KERNEL);
    new->srtt = n;
    new->next = NULL;

    if(sbflows[i].test_head->qlen == 0){
        //new->previous = NULL;
        new->next = new;
        sbflows[i].test_head->next = new;
        sbflows[i].test_head->previous = new;
    }else{
        last = sbflows[i].test_head->previous;
        last->next = new;
        //new->previous = last;
        new->next = sbflows[i].test_head->next;
        sbflows[i].test_head->previous = new;
    }
    sbflows[i].test_head->qlen++;
}

/* remove an element from the queue */
static void queue_del(unsigned int i){
    struct sbflw_rtt *last, *first, *old;

    if(sbflows[i].test_head->qlen == 0) return;

    sbflows[i].test_head->qlen--;
    /* since it's a queue, the removed element is the first one */
    old = sbflows[i].test_head->next;
    last = sbflows[i].test_head->previous;
    first = old->next;

    last->next = first;
    sbflows[i].test_head->next = first;
    kfree(old);
}
/* Returns the socket data from a given subflow socket */
static struct corrsched_sock_data *corrsched_get_sock_data(struct tcp_sock *tp)
{
     return (struct corrsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

 /* Returns the control block data from a given meta socket */
static struct corrsched_cb_data *corrsched_get_cb_data(struct tcp_sock *tp)
{
     return (struct corrsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static int compare(const void *a, const void *b){
    const struct sort_value *a_sort = a;
    const struct sort_value *b_sort = b;

    if(a_sort->value < b_sort->value) return -1;
    if(a_sort->value > b_sort->value) return 1;
    return 0;
}

/* Give a rank (sort) the RTTs queues */
static bool rtt_rank(struct mptcp_cb *mpcb){
    struct sbflw_rtt *tmp;
    unsigned int rank[MIN_RTT];
    unsigned int i, k;
    unsigned int j = 0;
    unsigned int u = 0, v = 0;
    s32 mean_ranking;
    unsigned int repeated = 0;
    struct sort_value rtts[MIN_RTT];

    for(i = 0; i < mpcb->cnt_subflows; i++){

        if(sbflows[i].test_head->qlen < MIN_RTT)
            continue;
        j = 0;
        tmp = sbflows[i].test_head->next;

        do{
            rtts[j].value = tmp->srtt;
            rtts[j].index = j;

            if(tmp->srtt != 0){
                sbflows[i].all_zero = 0;
            }
            j++;
            tmp = tmp->next;
        }while(tmp != sbflows[i].test_head->next);

        if(!sbflows[i].all_zero){
            sort(rtts, MIN_RTT, sizeof(struct sort_value), &compare, NULL);
            for(j = 0; j < MIN_RTT; j++){
                u = rtts[j].index;
                rank[u] = j;
            }

            for(j = 0; j < MIN_RTT; j++){
                if(rtts[j].value == rtts[j + 1].value){
                    for(u = j; u < MIN_RTT; u++){
                        mean_ranking = mean_ranking + u;
                        repeated = repeated + 1;
                        if(rtts[u + 1].value != rtts[u].value){
                            mean_ranking = mean_ranking / repeated;
                            for(v = j; v <= u; v++){
                                k = rtts[v].index;
                                if(mean_ranking > 0)
                                    rank[k] = mean_ranking;
                                else
                                    rank[k] = 1;
                            }
                            break;
                        }
                    }
                    j = u;
                }else{
                    k = rtts[j].index;
                    rank[k] = j;
                }
                repeated = 0;
                mean_ranking = 0;
            }
            j = 0;
            tmp = sbflows[i].test_head->next;
            do{
                tmp->r = rank[j];
                j++;
                tmp = tmp->next;
            }while(tmp != sbflows[i].test_head->next);
        }

    }
    return true;
}

// returns the index of the subflow with the smalles correlation
// value with another (returns the index of the "first" one)
static int corrsched_least_corr(struct mptcp_cb *mpcb,
                        unsigned int i,
                        s32 *state){
    unsigned int j;
    unsigned int p, q;
    s32 smallest = -1;
    s32 value = S32_MAX;

    q = sbflows[i].loc_id;
    for(j = 0; j < mpcb->cnt_subflows; j++){
        if(state[j])
            continue;

        if(sbflows[j].all_zero)
            continue;

        p = sbflows[j].loc_id;
        if(THRESHOLD(loc_id[p][q])){
            if(abs(loc_id[p][q]) < abs(value)){
                value = loc_id[p][q];
                smallest = j;
            }
        }
    }
    return smallest;
}


/* calculate the correlation between all active paths */
static void corrsched_corr_calc(struct mptcp_cb *mpcb,
                        struct tcp_sock *tp){
    struct tcp_sock *outer_first, *inner_first;
    struct tcp_sock *inner = tp, *outer = tp;
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int k = 0;
    s64 list_x[MIN_RTT];
    s64 list_y[MIN_RTT];
    s64 deviation_x = 0;
    s64 deviation_y = 0;
    s32 trunk = 1000;
    s64 sum = 0;
    s64 sum_x = 0;
    s64 sum_y = 0;
    s64 average_x = 0;
    s64 average_y = 0;
    s64 dev =0;
    s64 result;
    s64 b, y;
    s64 covariance = 0;
    s32 *state;
    s32 smallest = 0;
    struct sbflw_rtt *tmp;

    for(i = 0; i < mpcb->cnt_subflows; i++){
        least_corr[i].value = S64_MAX;
        least_corr[i].index = 0;
    }

    /* initialize the loc_id matrix */
    for(i = 0; i < mpcb->cnt_subflows; i++){
        for(j = 0; j < mpcb->cnt_subflows; j++){
            loc_id[i][j] = 0;
        }
    }

    rtt_rank(mpcb);

    state = kmalloc(sizeof(state) * mpcb->cnt_subflows, GFP_KERNEL);

    for(i = 0; i < mpcb->cnt_subflows; i++){
        k = 0;
        sum_x = 0;
        state[i] = 0;
        if(sbflows[i].all_zero) continue;
        /* get the list of values of x */
        tmp = sbflows[i].test_head->next;
        do{
            list_x[k] = tmp->r;
            sum_x += list_x[k];
            k++;
            tmp = tmp->next;
        }while(tmp != sbflows[i].test_head->next);
        for(j = i; j < mpcb->cnt_subflows; j++){
            k = 0;
            sum = 0;
            sum_y = 0;
            deviation_x = 0;
            deviation_y = 0;

            if(sbflows[j].all_zero){
                continue;
            }

            /* get the list of values of y and the sums of the
             * multiplication by values of x */
            tmp = sbflows[j].test_head->next;
            do{
                list_y[k] = tmp->r;
                sum+= list_x[k] * list_y[k];
                sum_y += list_y[k];
                k++;
                tmp = tmp->next;
            }while(tmp != sbflows[j].test_head->next);

            /* covariance: since correlation values usually are real numbers,
             * we multiply the values by 1000 to do the math with integers and
             * reduce the error */
            covariance = ((sum * trunk) - ((sum_x * sum_y) / MIN_RTT) * trunk) / MIN_RTT;

            /* standar deviation */
            average_x = sum_x / MIN_RTT;
            average_y = sum_y / MIN_RTT;

            for(k = 0; k < MIN_RTT; k++){
                deviation_x += (list_x[k] - average_x) * (list_x[k] - average_x);
                deviation_y += (list_y[k] - average_y) * (list_y[k] - average_y);
            }

            deviation_x = deviation_x / MIN_RTT;
            deviation_y = deviation_y / MIN_RTT;

            dev = deviation_x * deviation_y;
            dev = int_sqrt(dev);

            if(dev != 0)
                result = (covariance) / dev;
            else{
                if((deviation_x == 0) && (deviation_y == 0))
                    result = 1000;
                else
                    result = 0;

            }
            dev = 0;

            sbflows[i].corr[j] = result;
            sbflows[j].corr[i] = result;

            if(abs(result) > abs(loc_id[sbflows[i].loc_id][sbflows[j].loc_id])){
                loc_id[sbflows[i].loc_id][sbflows[j].loc_id] = result;
                loc_id[sbflows[j].loc_id][sbflows[i].loc_id] = result;
            }

	    /* stores the index and correlation value of the smalles correlation value
	     * calculated so far. Only the "first" one is stored here. For example, if
         * the smalles correlation is between the path 1 and 4. Here we'll store 1,
         * and later we'll find and store 4.
	     */
            if(THRESHOLD(result)){
                if(abs(result) < abs(least_corr[0].value)){
                    least_corr[0].value = result;
                    least_corr[0].index = i;
                    smallest = i;
                }
            }
        }
    }
    state[smallest] = 1;

    /*
     * to do: better name the variables used here
     * y stores the index of the subflow with the smallest correlation value
     * with the previously stored path (with smalles correlation among all pairs).
     */
        for(i = 0; i < mpcb->cnt_subflows; i++){
            y = corrsched_least_corr(mpcb, least_corr[i].index, state);
            if(y > 0){
                for(j = i; j < mpcb->cnt_subflows; j++){
                    if(least_corr[j].value == S64_MAX)
                        break;

                    b = corrsched_least_corr(mpcb, least_corr[j].index, state);
                    if(b != y){
                        break;
                    }
                }
                if(b == y){
                    least_corr[j].value = sbflows[y].corr[j-1];
                    least_corr[j].index = y;
                    state[y] = 1;
                }else
                    break;
            }
        }

    kfree(state);
}

static bool corrsched_get_active_valid_sks(struct sock *meta_sk)
{
     struct tcp_sock *meta_tp = tcp_sk(meta_sk);
     struct mptcp_cb *mpcb = meta_tp->mpcb;
     struct sock *sk;
     int active_valid_sks = 0;

     mptcp_for_each_sk(mpcb, sk) {
         if (subflow_is_active((struct tcp_sock *)sk) &&
             !mptcp_is_def_unavailable(sk))
             active_valid_sks++;
     }

     return active_valid_sks;
}

static bool corrsched_use_subflow(struct sock *meta_sk,
                 int active_valid_sks,
                 struct tcp_sock *tp,
                 struct sk_buff *skb)
{
    struct tcp_sock *meta_tp = tcp_sk(meta_sk);
    struct mptcp_cb *mpcb = meta_tp->mpcb;
    unsigned int i;
    bool listed = false;

    for(i = 0; i < mpcb->cnt_subflows; i++){
        if(least_corr[i].index == (tp->mptcp->path_index - 1)){
            listed = true;
            break;
        }
    }

    if (!skb || !mptcp_is_available((struct sock *)tp, skb, false))
        return false;

    if (TCP_SKB_CB(skb)->path_mask != 0)
	// if the current subflow is active and listed as a subflow with small correlation
        return subflow_is_active(tp) && listed;

    if (TCP_SKB_CB(skb)->path_mask == 0) {
        if (active_valid_sks == -1)
            active_valid_sks = corrsched_get_active_valid_sks(meta_sk);

        if (subflow_is_backup(tp) && active_valid_sks > 0)
            return false;
        else
            return true && listed;
    }

    return false;
}

/* allocate memory for a queue of subflows and their rtts */
/* to do: currently, you have to remove the module to "reset" the values
/* used. Later it would be necessary to make it in a way that the previously
/* stored values do not interfere with a new execution */
static void create_queue(void)
{
     int index = 0;

     if(sbflows == NULL){
         sbflows = kmalloc(sizeof(*sbflows) * MAX_SUBFLOWS, GFP_KERNEL);
         for(index = 0; index < MAX_SUBFLOWS; index++){
             sbflows[index].path_index = index + 1;

             sbflows[index].cap = 0;
             sbflows[index].cng = 0;
             sbflows[index].corr_value = 0;
             sbflows[index].corr = kmalloc(sizeof(*sbflows[index].corr) * MAX_SUBFLOWS, GFP_KERNEL);
             sbflows[index].test_head = kmalloc(sizeof(*sbflows[index].test_head), GFP_KERNEL);
             sbflows[index].test_head->qlen = 0;
             sbflows[index].all_zero = 1;
             sbflows[index].loc_id = U32_MAX;
             least_corr[index].value = S64_MAX;
             least_corr[index].index = 0;
         }
     }
}

static struct sock *correlation_get_subflow(struct sock *meta_sk,
                      struct sk_buff *skb,
                      bool zero_wnd_test)
{
    struct tcp_sock *meta_tp = tcp_sk(meta_sk);
    struct mptcp_cb *mpcb = meta_tp->mpcb;
    struct corrsched_cb_data *cb_data = corrsched_get_cb_data(meta_tp);
    struct tcp_sock *first_tp = cb_data->next_subflow;
    struct sock *sk;
    struct tcp_sock *tp;

    /* Answer data_fin on same subflow */
    if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
        skb && mptcp_is_data_fin(skb)) {
        mptcp_for_each_sk(mpcb, sk) {
            if (tcp_sk(sk)->mptcp->path_index ==
                mpcb->dfin_path_index &&
                mptcp_is_available(sk, skb, zero_wnd_test))
                return sk;
        }
    }

    if (!first_tp)
        first_tp = mpcb->connection_list;
    tp = first_tp;

    /* still NULL (no subflow in connection_list?) */
    if (!first_tp)
        return NULL;

    /* Search for any subflow to send it */
    do {
        if (mptcp_is_available((struct sock *)tp, skb,
                       zero_wnd_test)) {
            cb_data->next_subflow = tp->mptcp->next;
            return (struct sock *)tp;
        }

        tp = tp->mptcp->next;
        if (!tp)
            tp = mpcb->connection_list;
    } while (tp != first_tp);
    /* No space */
    return NULL;
}

/* Corrects the stored skb pointers if they are invalid */
static void corrsched_correct_skb_pointers(struct sock *meta_sk,
                      struct corrsched_sock_data *sk_data)
{
    struct tcp_sock *meta_tp = tcp_sk(meta_sk);

    if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una))
        sk_data->skb = NULL;
}


/* Returns the next skb from the queue */
static struct sk_buff *correlation_next_skb_from_queue(struct sk_buff_head *queue,
                             struct sk_buff *previous,
                             struct sock *meta_sk)
{
    if (skb_queue_empty(queue))
        return NULL;

    if (!previous)
        return skb_peek(queue);

    if (skb_queue_is_last(queue, previous))
        return NULL;

    /* sk_data->skb stores the last scheduled packet for this subflow.
     * If sk_data->skb was scheduled but not sent (e.g., due to nagle),
     * we have to schedule it again.
     *
     * For the correlation scheduler, there are two cases:
     * 1. sk_data->skb was not sent on another subflow:
     *    we have to schedule it again to ensure that we do not
     *    skip this packet.
     * 2. sk_data->skb was already sent on another subflow:
     *    with regard to the correlation semantic, we have to
     *    schedule it again. However, we keep it simple and ignore it,
     *    as it was already sent by another subflow.
     *    This might be changed in the future.
     *
     * For case 1, send_head is equal previous, as only a single
     * packet can be skipped.
     */
    if (tcp_send_head(meta_sk) == previous)
        return tcp_send_head(meta_sk);

    return skb_queue_next(queue, previous);
}

static struct sk_buff *correlation_next_segment(struct sock *meta_sk,
                          int *reinject,
                          struct sock **subsk,
                          unsigned int *limit)
{
    struct tcp_sock *meta_tp = tcp_sk(meta_sk);
    struct mptcp_cb *mpcb = meta_tp->mpcb;
    struct corrsched_cb_data *cb_data = corrsched_get_cb_data(meta_tp);
    struct tcp_sock *first_tp = cb_data->next_subflow;
    struct tcp_sock *tp;
    struct sk_buff *skb;
    int active_valid_sks = -1;
    unsigned int i = 0;
    /* As we set it, we have to reset it as well. */
    *limit = 0;
    if (skb_queue_empty(&mpcb->reinject_queue) &&
        skb_queue_empty(&meta_sk->sk_write_queue))
        /* Nothing to send */
        return NULL;

    /* First try reinjections */
    skb = skb_peek(&mpcb->reinject_queue);
    if (skb) {
        *subsk = get_available_subflow(meta_sk, skb, false);
        if (!*subsk)
            return NULL;
        *reinject = 1;
        return skb;
    }
    /* Then try indistinctly correlation and normal skbs */

    if (!first_tp)
        first_tp = mpcb->connection_list;

    /* still NULL (no subflow in connection_list?) */
    if (!first_tp)
        return NULL;

    tp = first_tp;

    /* creates the capture queue */
    if(cap_t == 0)
      cap_t = jiffies + (2 * HZ);

    if(time_after(jiffies, cap_t)){
        corrsched_corr_calc(mpcb, tp);
        cap_t = jiffies + (2 * HZ);
    }

    tp = first_tp;
    *reinject = 0;
    active_valid_sks = corrsched_get_active_valid_sks(meta_sk);
    do {
        struct corrsched_sock_data *sk_data;

        if(sbflows[tp->mptcp->path_index - 1].test_head->qlen == MIN_RTT)
            queue_del(tp->mptcp->path_index - 1);
        sbflows[tp->mptcp->path_index - 1].loc_id = tp->mptcp->loc_id;
        queue_add(tp->srtt_us, tp->mptcp->path_index - 1);

        /* Correct the skb pointers of the current subflow */
        sk_data = corrsched_get_sock_data(tp);
        corrsched_correct_skb_pointers(meta_sk, sk_data);

        skb = correlation_next_skb_from_queue(&meta_sk->sk_write_queue,
                            sk_data->skb, meta_sk);
        if (skb && corrsched_use_subflow(meta_sk, active_valid_sks, tp,
                        skb)) {
            sk_data->skb = skb;
            sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
            cb_data->next_subflow = tp->mptcp->next;
            *subsk = (struct sock *)tp;
            if (TCP_SKB_CB(skb)->path_mask)
                *reinject = -1;
            return skb;
        }

        tp = tp->mptcp->next;
        if (!tp)
            tp = mpcb->connection_list;
    }while (tp != first_tp);

    /* Nothing to send */
    return NULL;
}

static void correlation_release(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct corrsched_cb_data *cb_data = corrsched_get_cb_data(tp);

    /* Check if the next subflow would be the released one. If yes correct
     * the pointer
     */
    if (cb_data->next_subflow == tp)
        cb_data->next_subflow = tp->mptcp->next;
}

static struct mptcp_sched_ops mptcp_sched_correlation = {
    .get_subflow = correlation_get_subflow,
    .next_segment = correlation_next_segment,
    .release = correlation_release,
    .name = "correlation",
    .owner = THIS_MODULE,
};

static int __init correlation_register(void)
{
    BUILD_BUG_ON(sizeof(struct corrsched_sock_data) > MPTCP_SCHED_SIZE);
    BUILD_BUG_ON(sizeof(struct corrsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

    create_queue();
    if (mptcp_register_scheduler(&mptcp_sched_correlation))
        return -1;

    return 0;
}
static void correlation_unregister(void)
{
    mptcp_unregister_scheduler(&mptcp_sched_correlation);
}

module_init(correlation_register);
module_exit(correlation_unregister);

MODULE_AUTHOR("Igor Steuck Lopes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Correlation MPTCP");
MODULE_VERSION("0.90");

