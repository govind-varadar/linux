#ifndef _SCSI_LOGGING_H
#define _SCSI_LOGGING_H


/*
 * This defines the scsi logging feature.  It is a means by which the user
 * can select how much information they get about various goings on, and it
 * can be really useful for fault tracing.  The logging word is divided into
 * 8 nibbles, each of which describes a loglevel.  The division of things is
 * somewhat arbitrary, and the division of the word could be changed if it
 * were really needed for any reason.  The numbers below are the only place
 * where these are specified.  For a first go-around, 3 bits is more than
 * enough, since this gives 8 levels of logging (really 7, since 0 is always
 * off).  Cutting to 2 bits might be wise at some point.
 */

#define SCSI_LOG_ERROR_SHIFT              0
#define SCSI_LOG_TIMEOUT_SHIFT            3
#define SCSI_LOG_SCAN_SHIFT               6
#define SCSI_LOG_MLQUEUE_SHIFT            9
#define SCSI_LOG_MLCOMPLETE_SHIFT         12
#define SCSI_LOG_LLQUEUE_SHIFT            15
#define SCSI_LOG_LLCOMPLETE_SHIFT         18
#define SCSI_LOG_HLQUEUE_SHIFT            21
#define SCSI_LOG_HLCOMPLETE_SHIFT         24
#define SCSI_LOG_IOCTL_SHIFT              27

#define SCSI_LOG_ERROR_BITS               3
#define SCSI_LOG_TIMEOUT_BITS             3
#define SCSI_LOG_SCAN_BITS                3
#define SCSI_LOG_MLQUEUE_BITS             3
#define SCSI_LOG_MLCOMPLETE_BITS          3
#define SCSI_LOG_LLQUEUE_BITS             3
#define SCSI_LOG_LLCOMPLETE_BITS          3
#define SCSI_LOG_HLQUEUE_BITS             3
#define SCSI_LOG_HLCOMPLETE_BITS          3
#define SCSI_LOG_IOCTL_BITS               3

extern unsigned int scsi_logging_level;

#ifdef CONFIG_SCSI_LOGGING

#define SCSI_LOG_LEVEL(SHIFT, BITS)				\
        ((scsi_logging_level >> (SHIFT)) & ((1 << (BITS)) - 1))

#define SCSI_CHECK_LOGGING(SHIFT, BITS, LEVEL, CMD)		\
do {								\
	if (unlikely((SCSI_LOG_LEVEL(SHIFT, BITS)) > (LEVEL)))	\
		do {						\
			CMD;					\
		} while (0);					\
} while (0)

#define SHOST_CHECK_LOGGING(SHIFT, BITS, PRIO, SHOST, LEVEL, FMT, ARGS...) \
do {								\
	if (unlikely((SCSI_LOG_LEVEL(SHIFT, BITS)) > (LEVEL)))	\
		do {						\
			shost_printk(PRIO, SHOST, FMT, ##ARGS);	\
		} while (0);					\
} while (0)
#define STARGET_CHECK_LOGGING(SHIFT, BITS, PRIO, STARGET, LEVEL, FMT, ARGS...) \
do {								\
	if (unlikely((SCSI_LOG_LEVEL(SHIFT, BITS)) > (LEVEL)))	\
		do {						\
			starget_printk(PRIO, STARGET, FMT, ##ARGS);	\
		} while (0);					\
} while (0)
#define SDEV_CHECK_LOGGING(SHIFT, BITS, PRIO, SDEV, LEVEL, FMT, ARGS...) \
do {								\
	if (unlikely((SCSI_LOG_LEVEL(SHIFT, BITS)) > (LEVEL)))	\
		do {						\
			sdev_printk(PRIO, SDEV, FMT, ##ARGS);	\
		} while (0);					\
} while (0)
#define SCMD_CHECK_LOGGING(SHIFT, BITS, PRIO, SCMD, LEVEL, FMT, ARGS...) \
do {								\
	if (unlikely((SCSI_LOG_LEVEL(SHIFT, BITS)) > (LEVEL)))	\
		do {						\
			scmd_printk(PRIO, SCMD, FMT, ##ARGS);	\
		} while (0);					\
} while (0)
#else
#define SCSI_CHECK_LOGGING(SHIFT, BITS, LEVEL, CMD)
#endif /* CONFIG_SCSI_LOGGING */

/*
 * These are the macros that are actually used throughout the code to
 * log events.  If logging isn't enabled, they are no-ops and will be
 * completely absent from the user's code.
 */
#define SHOST_LOG_ERROR_RECOVERY(LEVEL,PRIO,SHOST,FMT,ARG...)		\
	SHOST_CHECK_LOGGING(SCSI_LOG_ERROR_SHIFT,			\
			    SCSI_LOG_ERROR_BITS,			\
			    PRIO, SHOST, LEVEL, FMT, ##ARG);
#define SDEV_LOG_ERROR_RECOVERY(LEVEL,PRIO,SDEV,FMT,ARG...)		\
	SDEV_CHECK_LOGGING(SCSI_LOG_ERROR_SHIFT,			\
			   SCSI_LOG_ERROR_BITS, \
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define SCMD_LOG_ERROR_RECOVERY(LEVEL,PRIO,SCMD,FMT,ARG...)		\
	SCMD_CHECK_LOGGING(SCSI_LOG_ERROR_SHIFT,			\
			   SCSI_LOG_ERROR_BITS, \
			   PRIO, SCMD, LEVEL, FMT, ##ARG);
#define SDEV_LOG_TIMEOUT(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_TIMEOUT_SHIFT,			\
			   SCSI_LOG_TIMEOUT_BITS,			\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define SDEV_LOG_SCAN_BUS(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_SCAN_SHIFT,				\
			   SCSI_LOG_SCAN_BITS,				\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define STARGET_LOG_SCAN_BUS(LEVEL,PRIO,STARGET,FMT,ARG...)		\
	STARGET_CHECK_LOGGING(SCSI_LOG_SCAN_SHIFT,			\
			      SCSI_LOG_SCAN_BITS,			\
			      PRIO, STARGET, LEVEL, FMT, ##ARG);
#define SHOST_LOG_SCAN_BUS(LEVEL,PRIO,SHOST,FMT,ARG...)			\
	SHOST_CHECK_LOGGING(SCSI_LOG_SCAN_SHIFT,			\
			    SCSI_LOG_SCAN_BITS,				\
			    PRIO, SHOST, LEVEL, FMT, ##ARG);
#define SDEV_LOG_MLQUEUE(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_MLQUEUE_SHIFT,			\
			   SCSI_LOG_MLQUEUE_BITS,			\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define SCMD_LOG_MLQUEUE(LEVEL,PRIO,SCMD,FMT,ARG...)			\
	SCMD_CHECK_LOGGING(SCSI_LOG_MLQUEUE_SHIFT,			\
			   SCSI_LOG_MLQUEUE_BITS,			\
			   PRIO, SCMD, LEVEL, FMT, ##ARG);
#define SDEV_LOG_MLCOMPLETE(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_MLCOMPLETE_SHIFT,			\
			   SCSI_LOG_MLCOMPLETE_BITS,			\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define SCMD_LOG_MLCOMPLETE(LEVEL,PRIO,SCMD,FMT,ARG...)			\
	SCMD_CHECK_LOGGING(SCSI_LOG_MLCOMPLETE_SHIFT,			\
			   SCSI_LOG_MLCOMPLETE_BITS,			\
			   PRIO, SCMD, LEVEL, FMT, ##ARG);
#define SCSI_LOG_HLQUEUE(LEVEL,CMD)			\
	SCSI_CHECK_LOGGING(SCSI_LOG_HLQUEUE_SHIFT,			\
			   SCSI_LOG_HLQUEUE_BITS,			\
			   LEVEL, CMD);
#define SCMD_LOG_HLQUEUE(LEVEL,PRIO,SCMD,FMT,ARG...)			\
	SCMD_CHECK_LOGGING(SCSI_LOG_HLQUEUE_SHIFT,			\
			   SCSI_LOG_HLQUEUE_BITS,			\
			   PRIO, SCMD, LEVEL, FMT, ##ARG);
#define SDEV_LOG_HLQUEUE(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_HLQUEUE_SHIFT,			\
			   SCSI_LOG_HLQUEUE_BITS,			\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);
#define SCMD_LOG_HLCOMPLETE(LEVEL,PRIO,SCMD,FMT,ARG...)			\
	SCMD_CHECK_LOGGING(SCSI_LOG_HLCOMPLETE_SHIFT,			\
			   SCSI_LOG_HLCOMPLETE_BITS,			\
			   PRIO, SCMD, LEVEL, FMT, ##ARG);
#define SDEV_LOG_IOCTL(LEVEL,PRIO,SDEV,FMT,ARG...)			\
	SDEV_CHECK_LOGGING(SCSI_LOG_IOCTL_SHIFT, SCSI_LOG_IOCTL_BITS,	\
			   PRIO, SDEV, LEVEL, FMT, ##ARG);

#endif /* _SCSI_LOGGING_H */
