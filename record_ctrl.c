#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/types.h>
#include <stdlib.h>
#include <termios.h>
#include <limits.h>
#include <sys/mman.h>
#include <fcntl.h>

#define LOGGER_IOC_MAGIC 0XAF
#define LOGGER_FLUSH	_IO(LOGGER_IOC_MAGIC, 0)

/*
 * @fname: the file name of the device to map
 * @fname_log: the output file name of the log
 */
int log2file(const char *fname, const char *fname_log)
{
	FILE *f;
	FILE *f_log;
	unsigned long offset = 0, len = 4096;
	void *address = (void*)-1;
	char *str;
	int result;
	char buf[4096];

	/* Open the file to map */
	if(!(f = fopen(fname, "r"))) {
		fprintf(stderr, "Fail to open %s: %s\n", fname, strerror(errno));
		return -1;
	}

	/* Open the file to write the log into */
	if(!(f_log = fopen(fname_log, "w"))) {
		fprintf(stderr, "Fail to open %s to write into: %s\n", fname_log, strerror(errno));
		return -1;
	}

	printf("Start logging. Use flush command to stop\n");
	while(1) {
		/* Mmap */
		result = fread(buf, 1, len, f);
		if(result != len) {
			/* The kernel has flushed the data */
			if(feof(f)) {
				/* Now data are in buf */
				if(fwrite(buf, 1, result, f_log) != result){
					fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
					fclose(f);
					fclose(f_log);
					exit(1);
				}
				/* Finish */
				break;
			}else {
				fprintf(stderr, "fread file() %s error:%s\n", fname, strerror(errno));
				fclose(f);
				fclose(f_log);
				return -1;
			}
		}

		/* Mmap and read the data */
		address = mmap(0, len, PROT_READ, MAP_LOCKED | MAP_SHARED, fileno(f), offset);
		if(address == (void *)-1) {
			fprintf(stderr, "mmap() %s error:%s\n",fname, strerror(errno));
			fclose(f);
			fclose(f_log);
			return -1;
		}
			
		/* Output the log to fname_log */
		str = (char*)address;
		if(fwrite(str, len, 1, f_log) != 1){
			fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
			fclose(f);
			fclose(f_log);
			return -1;
		}

		/* The driver will delete the data that mapped currently,
		 * so when we map the same address next time, it will
		 * actually be the next page.
		 */
		munmap(address, len);
		address = (void *)-1;
	}

	printf("Logged into file %s\n", fname_log);
	fclose(f);
	fclose(f_log);
	return 0;
}

int help() {
	fprintf(stderr, "Usage: \n"
			"record_ctrl <enable/disable> [log_file]\n\n"
			"record_ctrl flush\n"
			"\tFlushes all the data out to the <log_file>. This will stop writting more data\n"
			"\tto the logger module and flush all the remaining data out to the <log_file>. \n"
			"\tAfter that the record_ctrl will stop working and return. This command is normally\n"
			"\tused after the virtual machine being shutdowned.\n"
			"record_ctrl help\n"
			"\tDisplay this help information.\n");
	return -1;
}

int flush(void)
{
	int fd_logger;
	int ret;

	fd_logger = open("/dev/logger", 0);
	if(fd_logger < 0) {
		printf("Open /dev/logger failed\n");
		return -1;
	}
	ret = ioctl(fd_logger, LOGGER_FLUSH);
	if(ret < 0) {
		printf("Flush failed\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int record;

	if (argc < 2)
		return help();

	if(strcmp(argv[1], "flush") == 0) {
		return flush();
	} else if(strcmp(argv[1], "help") == 0) {
		return help();
	}

	if (strcmp(argv[1], "enable") == 0)
		record = 1;
	else if (strcmp(argv[1], "disable") == 0)
		record = 0;
	else {
		fprintf(stderr, "Unknow command : %s\n", argv[1]);
		return help();
	}

	if (record) {
		const char *fname_log = "kern.log";

		if(argc == 3) {
			fname_log = argv[2];
		} else {
			printf("Use default log file name: kern.log\n");
		}

		log2file("/dev/logger", fname_log);
	}
	return 0;
}
