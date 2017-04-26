/*
 * Copyright Bruh!
 */

#include "enic.h"

#define ENIC_TSTAMP_WRAP_SEC 240
#define ENIC_TSTAMP_OVERFLOW_PERIOD ((ENIC_TSTAMP_WRAP_SEC - 30) * HZ)

void enic_fill_hwstamp(struct enic_tstamp *tstamp, u64 timestamp,
		       struct skb_shared_hwtstamps *hwts)
{
	u64 nsec;

	spin_lock_bh(&tstamp->lock);
	nsec = timecounter_cyc2time(&tstamp->clock, timestamp);
	spin_unlock_bh(&tstamp->lock);
	hwts->hwtstamp = ns_to_ktime(nsec);
}

static u64 enic_read_cycle(const struct cyclecounter *cc)
{
	u64 a0, a1;
	struct enic_tstamp *tstamp = container_of(cc, struct enic_tstamp,
						  cycles);
	struct enic *enic = container_of(tstamp, struct enic, tstamp);

	spin_lock_bh(&enic->devcmd_lock);
	vnic_dev_cmd(enic->vdev, CMD_HW_TIMESTAMP_GET, &a0, &a1, 1000);
	spin_unlock_bh(&enic->devcmd_lock);

	return a0 & cc->mask;
}

static void enic_cycle_overflow(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct enic_tstamp *tstamp = container_of(dwork, struct enic_tstamp,
						  overflow_work);

	spin_lock_bh(&tstamp->lock);
	timecounter_read(&tstamp->clock);
	spin_unlock_bh(&tstamp->lock);
	schedule_delayed_work(&tstamp->overflow_work, tstamp->overflow_period);
}

int enic_hwstamp_set(struct net_device *netdev, struct ifreq *ifr)
{
	struct enic *enic = netdev_priv(netdev);
	struct hwtstamp_config config;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	switch (config.tx_type) {
	case HWTSTAMP_TX_OFF:
		netdev_info(netdev, "tx tstamp off");
		break;
	case HWTSTAMP_TX_ON:
		netdev_info(netdev, "tx tstamp on");
		break;
	default:
		return -ERANGE;
	}

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
	case HWTSTAMP_FILTER_ALL:
		config.rx_filter = HWTSTAMP_FILTER_NONE;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;

		break;
	}

	memcpy(&enic->tstamp.hwtstamp_config, &config, sizeof(config));

	return copy_to_user(ifr->ifr_data, &config,
			    sizeof(config)) ? -EFAULT : 0;
}

int enic_hwstamp_get(struct net_device *netdev, struct ifreq *ifr)
{
	struct enic *enic = netdev_priv(netdev);
	struct hwtstamp_config *cfg = &enic->tstamp.hwtstamp_config;

	return copy_to_user(ifr->ifr_data, cfg, sizeof(*cfg)) ? -EFAULT : 0;
}

static int enic_ptp_settime(struct ptp_clock_info *ptp,
			    const struct timespec64 *ts)
{
	u64 ns = timespec64_to_ns(ts);
	struct enic_tstamp *tstamp = container_of(ptp, struct enic_tstamp,
						  ptp_info);

	spin_lock_bh(&tstamp->lock);
	timecounter_init(&tstamp->clock, &tstamp->cycles, ns);
	spin_unlock_bh(&tstamp->lock);

	return 0;
}

static int enic_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct enic_tstamp *tstamp = container_of(ptp, struct enic_tstamp,
						  ptp_info);
	u64 ns;

	spin_lock_bh(&tstamp->lock);
	ns = timecounter_read(&tstamp->clock);
	spin_unlock_bh(&tstamp->lock);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int enic_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct enic_tstamp *tstamp = container_of(ptp, struct enic_tstamp,
						  ptp_info);

	spin_lock_bh(&tstamp->lock);
	timecounter_adjtime(&tstamp->clock, delta);
	tstamp->adjtime += delta;
	spin_unlock_bh(&tstamp->lock);

	return 0;
}

static int enic_ptp_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	u64 adj;
	u32 diff;
	int neg_adj = 0;
	struct enic_tstamp *tstamp = container_of(ptp, struct enic_tstamp,
						  ptp_info);

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}

	adj = tstamp->nominal_c_mult;
	adj *= delta;
	diff = div_u64(adj, 1000000000ULL);

	spin_lock_bh(&tstamp->lock);
	timecounter_read(&tstamp->clock);
	tstamp->cycles.mult = neg_adj ? tstamp->nominal_c_mult - diff :
					tstamp->nominal_c_mult + diff;
	spin_unlock_bh(&tstamp->lock);

	return 0;
}

static const struct ptp_clock_info enic_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.max_adj	= 1000000000,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfreq	= enic_ptp_adjfreq,
	.adjtime	= enic_ptp_adjtime,
	.gettime64	= enic_ptp_gettime,
	.settime64	= enic_ptp_settime,
	.enable		= NULL,
};

void enic_tstamp_init(struct enic *enic)
{
	ktime_t time;
	u64 dev_freq, a1;
	struct enic_tstamp *tstamp = &enic->tstamp;

	tstamp->hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
	tstamp->hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;

	spin_lock_bh(&enic->devcmd_lock);
	time = ktime_get_real();
	vnic_dev_cmd(enic->vdev, CMD_HW_CLOCK_GET, &dev_freq, &a1, 1000);
	spin_unlock_bh(&enic->devcmd_lock);

	spin_lock_init(&tstamp->lock);
	tstamp->freq = dev_freq;
	if (!tstamp->freq) {
		netdev_info(enic->netdev, "HW timestamping not supported");

		return;
	}
	tstamp->cycles.read = enic_read_cycle;
	tstamp->cycles.shift = freq_to_shift(dev_freq, ENIC_TSTAMP_WRAP_SEC);
	tstamp->cycles.mult = clocksource_khz2mult(dev_freq * 1000,
						   tstamp->cycles.shift);
	tstamp->nominal_c_mult = tstamp->cycles.mult;
	tstamp->cycles.mask = CLOCKSOURCE_MASK(48);
	timecounter_init(&tstamp->clock, &tstamp->cycles,
			 ktime_to_ns(time));
	tstamp->adjtime = 0;
	netdev_info(enic->netdev, "init tstamp: clock: %d, shift: %d, mult: %u",
		    (u32)dev_freq, tstamp->cycles.shift, tstamp->cycles.mult);
	tstamp->overflow_period = ENIC_TSTAMP_OVERFLOW_PERIOD;

	tstamp->ptp_info = enic_ptp_clock_info;
	snprintf(tstamp->ptp_info.name, 16, "enic ptp");
	tstamp->ptp = ptp_clock_register(&tstamp->ptp_info, enic_get_dev(enic));
	if (IS_ERR_OR_NULL(tstamp->ptp)) {
		netdev_warn(enic->netdev, "ptp_clock_register failed %ld",
			    PTR_ERR(tstamp->ptp));
		tstamp->ptp = NULL;
	}
	INIT_DELAYED_WORK(&tstamp->overflow_work, enic_cycle_overflow);
	schedule_delayed_work(&tstamp->overflow_work, 0);
}

void enic_tstamp_cleanup(struct enic *enic)
{
	struct enic_tstamp *tstamp = &enic->tstamp;

	if (!tstamp->freq)
		return;
	if (tstamp->ptp) {
		ptp_clock_unregister(tstamp->ptp);
		tstamp->ptp = NULL;
	}
	cancel_delayed_work_sync(&tstamp->overflow_work);
}

