#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>

void prealloc() {
	const int len = 0x10000;
	volatile int arg[len];
	for (int i=0; i<len; i++)
		arg[i]=0;
	asm volatile ("":::"memory");
}

int parseFloat(const char* in, double *out) {
	const char* end = in;
	double o = strtod(in, (char**)&end);
	if (*end!='\0')
		return 1;
	if (out)
		*out = o;
	return 0;
}

void usage(const char *progname) {
	const char help0[] =
		"Usage: ";
	const char help1[] =
		" [OPTION]... CANARY [ARG]...\n"
		"Userspace OOM killer.\n"
		"\n"
		"Run CANARY every INTERVAL.\n"
		"If it runs for longer than TIMEOUT, kill process with highest OOM score.\n"
		"\n"
		"Options:\n"
		"\n"
		"    -i INTERVAL     canary interval, in seconds (default: 5.0)\n"
		"    -t TIMEOUT      timeout, in seconds (default: 15.0)\n"
		"    --help       show this text and exit\n"
		"\n";
	write(STDERR_FILENO,help0,sizeof(help0)-1);
	write(STDERR_FILENO,progname,strlen(progname));
	write(STDERR_FILENO,help1,sizeof(help1)-1);
}

unsigned long long mstime() {
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC,&t)) {
		abort();
	}
	unsigned long long ms = t.tv_sec*1000;
	ms += t.tv_nsec / 1000000;
	return ms;
}

struct linux_dirent {
	unsigned long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

void killer() {
	const char err[] = "FREEZE DETECTED. engaging OOM killer.\n";
	write(STDERR_FILENO,err,sizeof(err)-1);
	const int buf_size = 8192;
	char buf[buf_size];
	int fd = open("/proc", O_RDONLY | O_DIRECTORY);
	if (fd == -1) {
		const char err[] = "error: failed to open /proc\n";
		write(STDERR_FILENO,err,sizeof(err)-1);
		abort();
	}
	ssize_t c;
	double maxscore = -1;
	pid_t killee;
	while ((c = syscall(SYS_getdents, fd, buf, buf_size)) && c != -1) {
		size_t bpos = 0;
		for (size_t bpos=0; bpos < c;) {
			struct linux_dirent *d = (void*)(buf + bpos);
			double pidf;
			if (!parseFloat(d->d_name, &pidf)) {
				pid_t pid = pidf;
				const char psuf[] = "/oom_score";
				int nlen = strlen(d->d_name);
				int buf_size = sizeof(psuf) + nlen;
				char buf[buf_size];
				memcpy(buf, d->d_name, nlen);
				memcpy(buf+nlen, (void*)psuf, sizeof(psuf));
				int pfd = openat(fd, buf, O_RDONLY);
				if (pfd == -1) {
					fprintf(stderr,"error: failed to open %s: %s\n", buf, strerror(errno));
				} else {
					const int osbuf_size = 256;
					char osbuf[osbuf_size];
					ssize_t osl = read(pfd, osbuf, osbuf_size);
					if (osl < 2) {
						const char err[] = "error: failed to read oom_score\n";
						write(STDERR_FILENO,err,sizeof(err)-1);
						abort();
					}
					if (osbuf[osl-1] == '\n')
						osbuf[osl-1] = '\0'; // eat the newline;
					double oomsc;
					if (parseFloat(osbuf, &oomsc)) {
						const char err[] = "error: failed to parse oom_score\n";
						write(STDERR_FILENO,err,sizeof(err)-1);
						abort();
					}
					if (maxscore < oomsc) {
						maxscore = oomsc;
						killee = pid;
					}
					close(pfd);
				}
			}
			bpos += d->d_reclen;
		}
	}
	if (c==-1) {
		const char err[] = "error: failed to read dir\n";
		write(STDERR_FILENO,err,sizeof(err)-1);
		abort();
	}
	close(fd);
	kill(killee, SIGKILL);
	fprintf(stderr,"Killed %lli.\n", (long long)killee);
}

int forker(int pin, int port, int argc, char **argv) {
	for (;;) {
		char tok;
		if (!read(pin, &tok, sizeof(tok)))
			return 1;
		pid_t pid;
		pid = fork();
		if (pid) {
			write(port, &pid, sizeof(pid));
			if (pid == -1)
				continue;
		}
		if (!pid) {
			close(pin); close(port);
			if (execvp(*argv,argv)) {
				const char err[] = "error: failed to execute canary\n";
				write(STDERR_FILENO,err,sizeof(err)-1);
				return 1;
			}
			return 0;
		}
		pid_t wpid = waitpid(pid, NULL, 0);
		write(port, &wpid, sizeof(wpid));
	}
}

int dog(int pin, int port, long long ival, long long tout) {
	for (;;) {
		write(port,"",1);
		pid_t pid;
		if (!read(pin,&pid,sizeof(pid))) {
			const char err[] = "error: dog fail read pid from forker\n";
			write(STDERR_FILENO,err,sizeof(err)-1);
			return 1;
		}
		if (pid == -1) {
			killer();
			continue;
		}
		pid_t wpid;
		struct timeval toutv = (struct timeval){
			.tv_sec = tout/1000,
			.tv_usec = (tout%1000)*1000
		};
		fd_set sfds;
		FD_ZERO(&sfds);
		FD_SET(pin,&sfds);
		int selc = select(FD_SETSIZE,&sfds,NULL,NULL,&toutv);
		if (selc == -1) {
			const char err[] = "error: select fail\n";
			write(STDERR_FILENO,err,sizeof(err)-1);
			return 1;
		}
		if (selc == 0) {
			kill(pid,SIGKILL);
			killer();
			read(pin,&wpid,sizeof(wpid));
			continue;
		}
		if (!read(pin,&wpid,sizeof(wpid))) {
			const char err[] = "error: dog fail read waitpid from forker\n";
			write(STDERR_FILENO,err,sizeof(err)-1);
			return 1;
		}
		usleep(ival*1000);
	}
}

int main(int argc, char** argv) {
	prealloc();
	if (mlockall(MCL_CURRENT)) {
		const char err[] = "error: lock fail\n";
		write(STDERR_FILENO,err,sizeof(err)-1);
		return 1;
	}
	const char *progname = *argv++; argc--;
	unsigned long long ival;
	unsigned long long tout;
	double ivalf = 5.0f;
	double toutf = 15.0f;
	while (argc>0 && **argv == '-') {
		if(!strcmp(*argv,"-i")) {
			argv++; argc--; if (argc==0) {
				const char err[] = "error: interval expected\n";
				usage(progname);
				write(STDERR_FILENO,err,sizeof(err)-1);
				return 1;
			}
			const char *ivals = *argv++; argc--;
			if (parseFloat(ivals,&ivalf)) {
				const char err0[] = "invalid interval: ";
				const char err1[] = "\n";
				usage(progname);
				write(STDERR_FILENO,err0,sizeof(err0)-1);
				write(STDERR_FILENO,ivals,strlen(ivals));
				write(STDERR_FILENO,err1,sizeof(err1)-1);
				return 1;
			}
		} else if (!strcmp(*argv,"-t")) {
			argv++; argc--; if (argc==0) {
				const char err[] = "error: timeout expected\n";
				usage(progname);
				write(STDERR_FILENO,err,sizeof(err));
				return 1;
			}
			const char *touts = *argv++; argc--;
			if (parseFloat(touts,&toutf)) {
				const char err0[] = "invalid timeout: ";
				const char err1[] = "\n";
				usage(progname);
				write(STDERR_FILENO,err0,sizeof(err0)-1);
				write(STDERR_FILENO,touts,strlen(touts));
				write(STDERR_FILENO,err1,sizeof(err1)-1);
				return 1;
			}
		} else if (!strcmp(*argv,"--")) {
			argv++; argc--;
			break;
		} else if (!strcmp(*argv,"--help")) {
			usage(progname);
			return 0;
		} else {
			const char err0[] = "invalid argument: ";
			const char err1[] = "\n";
			usage(progname);
			write(STDERR_FILENO,err0,sizeof(err0)-1);
			write(STDERR_FILENO,*argv,strlen(*argv));
			write(STDERR_FILENO,err1,sizeof(err1)-1);
			return 1;
		}
	}
	ival = ivalf * 1000;
	tout = toutf * 1000;
	if (argc<1) {
		const char err[] = "error: commandname expected\n";
		usage(progname);
		write(STDERR_FILENO,err,sizeof(err)-1);
		return 1;
	}
	int pipes[2][2];
	pipe(pipes[0]);
	pipe(pipes[1]);
	pid_t pid = fork();
	if (pid==-1) {
		const char err[] = "error: fork fail\n";
		write(STDERR_FILENO,err,sizeof(err)-1);
		return 1;
	}
	if (pid) {
		close(pipes[0][1]);
		close(pipes[1][0]);
		return dog(pipes[0][0],pipes[1][1], ival, tout);
	} else {
		close(pipes[0][0]);
		close(pipes[1][1]);
		return forker(pipes[1][0],pipes[0][1], argc, argv);
	}
}
