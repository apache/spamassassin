#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    int pfds[2];
    int childpid;

    if ( pipe(pfds) == -1 ) {
	perror("Failed to create pipe; quitting\n");
	exit(1);
    }

    if ( ( childpid=fork() ) == -1 ) {
	perror("Failed to fork; quitting\n");
	exit(2);
    }

    if ( childpid == 0 ) {
        close(1);       /* close normal stdout */
        dup(pfds[1]);   /* make stdout same as pfds[1] */
        close(pfds[0]); /* we don't need this */
        execlp("spamc", "spamc", NULL);
    } else {
        close(0);       /* close normal stdin */
        dup(pfds[0]);   /* make stdin same as pfds[0] */
        close(pfds[1]); /* we don't need this */
        execlp("qmail-queue", "qmail-queue", NULL);
    }
}

