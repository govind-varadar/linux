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
	tstamp->cycles.read = enic_read_cycle;
	tstamp->cycles.shift = freq_to_shift(dev_freq, ENIC_TSTAMP_WRAP_SEC);
	tstamp->cycles.mult = clocksource_khz2mult(dev_freq * 1000,
						   tstamp->cycles.shift);
	tstamp->nominal_c_mult = tstamp->cycles.mult;
	tstamp->cycles.mask = CLOCKSOURCE_MASK(48);
	timecounter_init(&tstamp->clock, &tstamp->cycles,
			 ktime_to_ns(time));
	netdev_info(enic->netdev, "init tstamp: clock: %d, shift: %d, mult: %u",
		    (u32)dev_freq, tstamp->cycles.shift, tstamp->cycles.mult);
	tstamp->overflow_period = ENIC_TSTAMP_OVERFLOW_PERIOD;
	INIT_DELAYED_WORK(&tstamp->overflow_work, enic_cycle_overflow);
	schedule_delayed_work(&tstamp->overflow_work, 0);
}

void enic_tstamp_cleanup(struct enic *enic)
{
	struct enic_tstamp *tstamp = &enic->tstamp;

	cancel_delayed_work_sync(&tstamp->overflow_work);
}

