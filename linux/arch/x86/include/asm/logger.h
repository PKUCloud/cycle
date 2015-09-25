#ifndef _ASM_X86_LOGGER_H
#define _ASM_X86_LOGGER_H

extern int rr_log(const char* fmt, ...);

#define DEBUG_RECORD_REPLAY

#ifdef DEBUG_RECORD_REPLAY
enum {
	RR_DB_GEN,
};
#define RR_DBBIT(x)	(1 << RR_DB_##x)
static int rr_dbflags = RR_DBBIT(GEN);

#define RR_DLOG(what, fmt, ...) do { \
	if (rr_dbflags & RR_DBBIT(what)) { \
		rr_log("%s: " fmt "\n", __func__, \
		       ## __VA_ARGS__); } \
	} while (0)
#else
#define RR_DLOG(what, fmt, ...) do {} while (0)
#endif

#endif