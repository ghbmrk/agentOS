/* The loader's own record for tools/hostcheck.py (#5055, #5231): a glibc rtld-audit module
   (rtld-audit(7)), named by LD_AUDIT, that appends every name the loader is asked for or tries
   (la_objsearch) and the name of every object it maps (la_objopen), each ended by a NUL, to
   $AGENTOS_LOADER_RECORD.PID. A name holds no NUL, so the record cannot be misread, whatever
   bytes a name holds. A child forked without an exec appends to its parent's record. Each name
   opens the file anew, so a process that closes or reuses descriptors cannot lose or redirect
   it; any failure ends the process (exit 127), so a name is never left out. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char record[4096];

static void put(const char *name)
{
	size_t n = strlen(name) + 1;
	int fd = open(record, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

	if (fd < 0 || write(fd, name, n) != (ssize_t)n || close(fd) != 0)
		_exit(127);
}

unsigned int la_version(unsigned int version)
{
	const char *base = getenv("AGENTOS_LOADER_RECORD");
	int n;

	(void)version;
	if (base == NULL || base[0] != '/')
		_exit(127);
	n = snprintf(record, sizeof record, "%s.%d", base, (int)getpid());
	if (n < 0 || (size_t)n >= sizeof record)
		_exit(127);
	return LAV_CURRENT;
}

char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
	(void)cookie;
	(void)flag;
	put(name);
	return (char *)name;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
	(void)lmid;
	(void)cookie;
	put(map->l_name != NULL ? map->l_name : "");
	return 0;
}
