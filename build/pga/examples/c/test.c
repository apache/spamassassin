From levine@mcs.anl.gov Mon Nov 27 16:53:21 1995
Received: from jadoube (jadoube.mcs.anl.gov [140.221.7.137]) by antares.mcs.anl.gov (8.6.10/8.6.10)  with ESMTP
	id QAA23813 for <walenz@mcs.anl.gov>; Mon, 27 Nov 1995 16:53:21 -0600
From: David Levine <levine@mcs.anl.gov>
Date: Mon, 27 Nov 1995 16:53:19 -0600
Message-Id: <199511272253.QAA01962@jadoube>
To: walenz@mcs.anl.gov
Status: R


#include "pgapack.h"
double evaluate (PGAContext *ctx, int p, int pop);

int main(int argc, char **argv)
{
    PGAContext *ctx;
    int rank;

    ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
    PGASetUp   (ctx);
    rank = PGAGetRank(ctx, MPI_COMM_WORLD);
    PGAEvaluate(ctx, PGA_OLDPOP, evaluate, MPI_COMM_WORLD);
    if ( rank == 0 )
        PGAFitness (ctx, PGA_OLDPOP);
    while(!PGADone(ctx, MPI_COMM_WORLD)) {
        if ( rank == 0 ) {
            PGASelect                 (ctx, PGA_OLDPOP);
            PGARunMutationAndCrossover(ctx, PGA_OLDPOP, PGA_NEWPOP);
        }
        PGAEvaluate(ctx, PGA_OLDPOP, evaluate, MPI_COMM_WORLD);
        if ( rank == 0 )
            PGAFitness                (ctx, PGA_NEWPOP);
        PGAUpdateGeneration           (ctx, MPI_COMM_WORLD);
        if ( rank == 0 )
            PGAPrintReport            (ctx, stdout, PGA_OLDPOP);
    }
    PGADestroy(ctx);
    return(0);
}

