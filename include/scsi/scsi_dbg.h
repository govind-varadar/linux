#ifndef _SCSI_SCSI_DBG_H
#define _SCSI_SCSI_DBG_H

struct scsi_cmnd;
struct scsi_device;
struct scsi_sense_hdr;

extern void scsi_print_command(struct scsi_cmnd *);
extern void __scsi_print_command(unsigned char *);
extern void scsi_show_extd_sense(unsigned char, unsigned char, char *, int);
extern int scsi_show_sense_hdr(struct scsi_sense_hdr *, char *, int);
extern void scsi_print_sense_hdr(struct scsi_device *, const char *,
				 struct scsi_sense_hdr *);
extern void scsi_cmd_print_sense_hdr(struct scsi_cmnd *, const char *,
				     struct scsi_sense_hdr *);
extern void scsi_print_sense(char *, struct scsi_cmnd *);
extern void __scsi_print_sense(struct scsi_device *, const char *,
			       const unsigned char *, int);
extern void scsi_show_result(int, char *, int);
extern void scsi_print_result(struct scsi_cmnd *);
extern void scsi_print_status(unsigned char);
extern const char *scsi_sense_key_string(unsigned char);
extern const char *scsi_extd_sense_format(unsigned char, unsigned char,
					  const char **);

#endif /* _SCSI_SCSI_DBG_H */
