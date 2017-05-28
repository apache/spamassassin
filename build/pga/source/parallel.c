/*
COPYRIGHT

The following is a notice of limited availability of the code, and disclaimer
which must be included in the prologue of the code and in all source listings
of the code.

(C) COPYRIGHT 2008 University of Chicago

Permission is hereby granted to use, reproduce, prepare derivative works, and
to redistribute to others. This software was authored by:

D. Levine
Mathematics and Computer Science Division 
Argonne National Laboratory Group

with programming assistance of participants in Argonne National 
Laboratory's SERS program.

GOVERNMENT LICENSE

Portions of this material resulted from work developed under a
U.S. Government Contract and are subject to the following license: the
Government is granted for itself and others acting on its behalf a paid-up,
nonexclusive, irrevocable worldwide license in this computer software to
reproduce, prepare derivative works, and perform publicly and display
publicly.

DISCLAIMER

This computer code material was prepared, in part, as an account of work
sponsored by an agency of the United States Government. Neither the United
States, nor the University of Chicago, nor any of their employees, makes any
warranty express or implied, or assumes any legal liability or responsibility
for the accuracy, completeness, or usefulness of any information, apparatus,
product, or process disclosed, or represents that its use would not infringe
privately owned rights.
*/

/******************************************************************************
*     FILE: parallel.c: This file contains all the parallel functions
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
******************************************************************************/

#include "pgapack.h"

#define DEBUG_EVAL 0

/*U****************************************************************************
  PGARunGM - High-level routine to execute the genetic algorithm using the
  global model.  It is called after PGACreate and PGASetup have been called.
  If a NULL communicator is given, a sequential execution method is used,
  otherwise, work is divided among the processors in the communicator.

  Category: Generation

  Inputs:
    ctx      - context variable
    evaluate - a pointer to the user's evaluation function, which must
    have the calling sequence shown in the example.
    comm     - an MPI communicator

  Outputs:
    none

  Example:
    PGAContext *ctx;
    double f(PGAContext *ctx, int p, int pop);
    :
    PGARunGM(ctx, f, MPI_COMM_WORLD);

****************************************************************************U*/
void PGARunGM(PGAContext *ctx, double (*f)(PGAContext *, int, int),
	      MPI_Comm comm)
{
    int       rank, Restarted, best_p;
    void    (*CreateNewGeneration)(PGAContext *, int, int);

    /*  Let this be warned:
     *  The communicator is NOT duplicated.  There might be problems with
     *  PGAPack and the user program using the same communicator.
     */
    PGADebugEntered("PGARunGM");

    rank = PGAGetRank(ctx, comm);

    PGAEvaluate(ctx, PGA_OLDPOP, f, comm);
    if (rank == 0)
	PGAFitness(ctx, PGA_OLDPOP);

    if (PGAGetMutationOrCrossoverFlag(ctx)) 
	CreateNewGeneration = PGARunMutationOrCrossover;
    else
	CreateNewGeneration = PGARunMutationAndCrossover;

    while (!PGADone(ctx, comm)) {
	if (rank == 0) {
	    Restarted = PGA_FALSE;
	    if ((ctx->ga.restart == PGA_TRUE) &&
		(ctx->ga.ItersOfSame % ctx->ga.restartFreq == 0)) {
		ctx->ga.ItersOfSame++;
		Restarted = PGA_TRUE;
		PGARestart(ctx, PGA_OLDPOP, PGA_NEWPOP);
	    } else {
		PGASelect(ctx, PGA_OLDPOP);
		CreateNewGeneration(ctx, PGA_OLDPOP, PGA_NEWPOP);
	    }
	}
	MPI_Bcast(&Restarted, 1, MPI_INT, 0, comm);

	PGAEvaluate(ctx, PGA_NEWPOP, f, comm);
	if (rank == 0)
	    PGAFitness(ctx, PGA_NEWPOP);

	/*  If the GA wasn't restarted, update the generation and print
         *  stuff.  We do this because a restart is NOT counted as a 
         *  complete generation.
	 */
	if (!Restarted) {
	    PGAUpdateGeneration(ctx, comm);
	    if (rank == 0)
		PGAPrintReport(ctx, stdout, PGA_OLDPOP);
	}
    }

    if (rank == 0) {
	best_p = PGAGetBestIndex(ctx, PGA_OLDPOP);
	printf("The Best Evaluation: %e.\n",
	       PGAGetEvaluation(ctx, best_p, PGA_OLDPOP));
	printf("The Best String:\n");
	PGAPrintString(ctx, stdout, best_p, PGA_OLDPOP);
	fflush(stdout);
    }
    PGADebugExited("PGARunGM");
}


/*I****************************************************************************
   PGAEvaluateSeq - Internal evalution function.  Evaluates all strings
   that need to be evaluated using one processor.

   Category: Fitness & Evaluation

   Inputs:
      ctx  - context variable
      pop  - symbolic constant of the population to be evaluated
      f    - a pointer to a function to evaluate a string.

   Outputs:

   Example:

****************************************************************************I*/
void PGAEvaluateSeq(PGAContext *ctx, int pop,
		    double (*f)(PGAContext *, int, int))
{
    int     p;
    double  e;

    PGADebugEntered("PGAEvaluateSeq");

    /*  Standard sequential evaluation.  */
    if (ctx->sys.UserFortran == PGA_TRUE) {
	for (p=1; p<=ctx->ga.PopSize; p++)
	    if (!PGAGetEvaluationUpToDateFlag(ctx, p-1, pop)) {
		e = (*((double(*)(void *, void *, void *))f))(&ctx, &p, &pop);
		PGASetEvaluation (ctx, p-1, pop, e);
	    }
    } else {
	for (p=0; p<ctx->ga.PopSize; p++) 
	    if (!PGAGetEvaluationUpToDateFlag(ctx, p, pop)) {
		e = (*f)(ctx, p, pop);
		PGASetEvaluation(ctx, p, pop, e);
	    }
    }
    PGADebugExited("PGAEvaluateSeq");
}


/*I****************************************************************************
   PGAEvaluateCoop - Internal evaluation function.  Evaluates all strings
   that need to be evaluated using two processors cooperatively.  The first
   is treated as a master, it will send a string to the second for evaluation.
   While the second is evaluating, the master will _also_ evaluate a string.

   Category: Fitness & Evaluation

   Inputs:
      ctx  - context variable
      pop  - symbolic constant of the population to be evaluated
      f    - a pointer to a function to evaluate a string.
      comm - an MPI communicator

   Outputs:

   Example:

****************************************************************************I*/
void PGAEvaluateCoop(PGAContext *ctx, int pop,
		     double (*f)(PGAContext *, int, int), MPI_Comm comm)
{
    MPI_Status      stat;
    int             p, fp, q;
    double          e;
    PGAIndividual  *ind;

    PGADebugEntered("PGAEvaluateCoop");

    q = -1;

    ind = PGAGetIndividual(ctx, 0, pop);
    
    for (p=0; p<ctx->ga.PopSize;) {
	while ((p<ctx->ga.PopSize) && (ind+p)->evaluptodate)  p++;
	if (p<ctx->ga.PopSize) {
	    PGASendIndividual(ctx, p, pop, 1, PGA_COMM_STRINGTOEVAL, comm);
	    q = p;
	}
	p++;
	
	while ((p<ctx->ga.PopSize) && (ind+p)->evaluptodate)  p++;
	if (p<ctx->ga.PopSize) {
	    if (ctx->sys.UserFortran == PGA_TRUE) {
		fp = p+1;
		e = (*((double(*)(void *, void *, void *))f))(&ctx, &fp, &pop);
	    } else {
		e = (*f)(ctx, p, pop);
	    }
	    PGASetEvaluation(ctx, p, pop, e);
#if DEBUG_EVAL
	    printf("%4d: %10.8e Local\n", p, e); fflush(stdout);
#endif
	}
	
	if (q >= 0) {
	    MPI_Recv(&e, 1, MPI_DOUBLE, 1, PGA_COMM_EVALOFSTRING, comm, &stat);
	    PGASetEvaluation(ctx, q, pop, e);
#if DEBUG_EVAL
	    printf("%4d: %10.8e Slave %d\n", p, e, 1); fflush(stdout);
#endif
	    q = -1;
	}
    }   
    
    /*  Release the slave  */
    MPI_Send(&q, 1, MPI_INT, 1, PGA_COMM_DONEWITHEVALS, comm);

    PGADebugExited("PGAEvaluateCoop");
}



/*I****************************************************************************
   PGAEvaluateMS - Internal evaluation function.  Evaluates all strings
   that need evaluating using three or more processors.  Operates in a 
   standard master-slave execution method.

   Category: Fitness & Evaluation

   Inputs:
      ctx  - context variable
      pop  - symbolic constant of the population to be evaluated
      f    - a pointer to a function to evaluate a string.
      comm - an MPI communicator

   Outputs:

   Example:

****************************************************************************I*/
void PGAEvaluateMS(PGAContext *ctx, int pop,
		   double (*f)(PGAContext *c, int p, int pop), MPI_Comm comm)
{
    int    *work;
    int     i, k, s, p, size, sentout;
    double  e;
    MPI_Status stat;
    PGAIndividual *ind;

    PGADebugEntered("PGAEvaluateMS");

    size = PGAGetNumProcs(ctx, comm);

    work = (int *)malloc(size *sizeof(int));
    if (work == NULL) {
	PGAError(ctx, "PGAEvaluateMS:  Couldn't allocate work array",
		 PGA_FATAL, PGA_VOID, NULL);
    }
    
    sentout = 0;
    s = 1;
    ind = PGAGetIndividual(ctx, 0, pop);
    
    /*  Send strings to all processes, since they are all unused.  */
    for (k=0; ((k<ctx->ga.PopSize) && (s<size)); k++) {
	if ((ind+k)->evaluptodate == PGA_FALSE) {
	    work[s] = k;
	    PGASendIndividual(ctx, k, pop, s, PGA_COMM_STRINGTOEVAL, comm);
#if DEBUG_EVAL
	    printf("%4d: Sent to slave %d.\n", k, s); fflush(stdout);
#endif
	    sentout++;
	    s++;
	}
    }
    
    /*  Move to the next string to be evaluated.  Notice that all we need
     *  to do is skip any strings that are already evaluated, unlike 
     *  below, where we need to _first_ go to the next string, then
     *  skip any that are up to date.
     */
    while ((k<ctx->ga.PopSize) && (ind+k)->evaluptodate)  k++;
    
    /*  While there are still unevaluated individuals, receive whatever
     *  is waiting, then immediately send a new string to it.  This 
     *  implicitly will balance the load across the machines, as we
     *  initially sent a string to _each_ process, so _each_ process
     *  will return an evaluation and get a new one immediately.
     */
    while(k<ctx->ga.PopSize) {
	/*  Receive the next evaluated string.  */
	MPI_Recv(&e, 1, MPI_DOUBLE, MPI_ANY_SOURCE, PGA_COMM_EVALOFSTRING,
		 comm, &stat);
	p = work[stat.MPI_SOURCE];
	PGASetEvaluation(ctx, p, pop, e);
	
#if DEBUG_EVAL
	printf("%4d: %10.8e Slave %d  Sent %d\n", work[stat.MPI_SOURCE],
	       e, stat.MPI_SOURCE, k); fflush(stdout);
#endif
	
	/*  Immediately send another string to be evaluated.  */
	work[stat.MPI_SOURCE] = k;
	PGASendIndividual(ctx, k, pop, stat.MPI_SOURCE,
			  PGA_COMM_STRINGTOEVAL, comm);
	
	/*  Find the next unevaluated individual  */
	k++;
	while ((k<ctx->ga.PopSize) && (ind+k)->evaluptodate)  k++;
    }
    
    /*  All strings have been sent out.  Wait for them to be done.  */
    while(sentout > 0) {
	MPI_Recv(&e, 1, MPI_DOUBLE, MPI_ANY_SOURCE, PGA_COMM_EVALOFSTRING,
		 comm, &stat);
	p = work[stat.MPI_SOURCE];
	PGASetEvaluation(ctx, p, pop, e);
	sentout--;
#if DEBUG_EVAL
	printf("%4d: %10.8e Slave %d\n", 
	       work[stat.MPI_SOURCE], e, stat.MPI_SOURCE); fflush(stdout);
#endif
    }
    free(work);
    
    /*  Release the slaves.  */
    for (i=1; i<size; i++)
	MPI_Send(&i, 1, MPI_INT, i, PGA_COMM_DONEWITHEVALS, comm);

    PGADebugExited("PGAEvaluateMS");
}


/*I****************************************************************************
   PGAEvaluateSlave - Slave execution routine.  Sit around and wait for a
   string to eval to show up, then evaluate it and return the evaluation.
   Terminates when it receives PGA_COMM_DONEWITHEVALS.

   Category: Fitness & Evaluation

   Inputs:

   Outputs:

   Example:

****************************************************************************I*/
void PGAEvaluateSlave(PGAContext *ctx, int pop,
		      double (*f)(PGAContext *, int, int), MPI_Comm comm)
{
    MPI_Status  stat;
    int         k;
    double      e;

    PGADebugEntered("PGAEvaluateSlave");

    k = PGA_TEMP1;
    MPI_Probe(0, MPI_ANY_TAG, comm, &stat);
    while (stat.MPI_TAG == PGA_COMM_STRINGTOEVAL) {
	PGAReceiveIndividual(ctx, PGA_TEMP1, pop, 0, PGA_COMM_STRINGTOEVAL,
			     comm, &stat);

	if (ctx->sys.UserFortran == PGA_TRUE)
	    e = (*((double(*)(void *, void *, void *))f))(&ctx, &k, &pop);
	else 
	    e = (*f)(ctx, PGA_TEMP1, pop);

	MPI_Send(&e, 1, MPI_DOUBLE, 0, PGA_COMM_EVALOFSTRING, comm);
	MPI_Probe(0, MPI_ANY_TAG, comm, &stat);
    }
    MPI_Recv(&k, 1, MPI_INT, 0, PGA_COMM_DONEWITHEVALS, comm, &stat);

    PGADebugExited("PGAEvaluateSlave");
}


/*U****************************************************************************
   PGAEvaluate - Calls a user-specified function to return an evaluation of
   each string in the population. The user-specified function is only called
   if the string has been changed (e.g., by crossover or mutation) or the user
   has explicitly signaled the string's evaluation is out-of-date by a call
   to PGASetEvaluationUpToDateFlag().

   Category: Fitness & Evaluation

   Inputs:
      ctx  - context variable
      pop  - symbolic constant of the population to be evaluated
      f    - a pointer to a function to evaluate a string.  This function will
             be called once for each string in population pop that requires
             evaluation.  This function must return a double (the evaluation
             function value) and must fit the prototype
                 double f(PGAContext *c, int p, int pop);
      comm - an MPI communicator

   Outputs:
      Evaluates the population via side effect

   Example:
      Evaluate all strings in population PGA_NEWPOP using the user-defined
      evaluation function Energy.

      double Energy(PGAContext *ctx, int p, int pop) {
        :
      };

      PGAContext *ctx;
      :
      PGAEvaluate(ctx, PGA_NEWPOP, Energy, MPI_COMM_WORLD);

****************************************************************************U*/
void PGAEvaluate(PGAContext *ctx, int pop,
		 double (*f)(PGAContext *, int, int), MPI_Comm comm)
{
    int  rank, size;

    PGADebugEntered("PGAEvaluate");

    rank = PGAGetRank(ctx, comm);
    size = PGAGetNumProcs(ctx, comm);

    if (rank == 0) {
	if (size == 1)
	    PGAEvaluateSeq(ctx, pop, f);
	if (size == 2)
	    PGAEvaluateCoop(ctx, pop, f, comm);
	if (size > 2) 
	    PGAEvaluateMS(ctx, pop, f, comm);
    } else {
	PGAEvaluateSlave(ctx, pop, f, comm);
    }

    PGADebugExited("PGAEvaluate");
}


/*U****************************************************************************
  PGABuildDatatype - Build an MPI datatype for string p in population pop.

  Category: Parallel

  Inputs:
    ctx     - context variable
    p       - index of an individual
    pop     - symbolic constant of the population

  Outputs:
    An MPI datatype for member p of population pop.

  Example:
    PGAContext *ctx;
    int p;
    MPI_Datatype dt;
    :
    dt = PGABuildDatatype(ctx, p, PGA_NEWPOP);

****************************************************************************U*/
MPI_Datatype PGABuildDatatype(PGAContext *ctx, int p, int pop)
{
    PGADebugEntered("PGABuildDatatype");
    
    PGADebugExited("PGABuildDatatype");

    return((*ctx->cops.BuildDatatype)(ctx, p, pop));
}


/*U****************************************************************************
  PGASendIndividual - transmit an individual to another process

  Category: Parallel

  Inputs:
    ctx  - context variable
    p    - index of an individual
    pop  - symbolic constant of the population
    dest - ID of the process where this is going
    tag  - MPI tag to send with the individual
    comm - MPI communicator

  Outputs:

  Example:
    PGAContext *ctx;
    int p, dest;
    :
    dest = SelectAFreeProcessor();
    PGASendIndividual(ctx, p, PGA_NEWPOP, dest, PGA_SR_STRINGTOEVAL, comm);

****************************************************************************U*/
void PGASendIndividual(PGAContext *ctx, int p, int pop, int dest, int tag,
                       MPI_Comm comm)
{
    MPI_Datatype individualtype;

    PGADebugEntered("PGASendIndividual");

    individualtype = PGABuildDatatype(ctx, p, pop);
    MPI_Send(MPI_BOTTOM, 1, individualtype, dest, tag, comm);
    MPI_Type_free(&individualtype);
    
    PGADebugExited("PGASendIndividual");
}

/*U****************************************************************************
  PGAReceiveIndividual - receive an individual from another process

  Category: Parallel

  Inputs:
    ctx    - contex variable
    p      - index of an individual
    pop    - symbolic constant of the population
    source - ID of the process from which to receive
    tag    - MPI tag to look for
    status - pointer to an MPI status structure

  Outputs:
    status and string p in population pop are changed by side-effect.

  Example:
    Receive a string from the master process (rank == 0) with tag
    PGA_SR_STRINGTOEVAL, and place it into the first temporary location
    in PGA_NEWPOP.

    PGAContext *ctx;
    MPI_Comm    comm;
    MPI_Status  status;
    :
    PGAReceiveIndividual(ctx, PGA_TEMP1, PGA_NEWPOP, 0, PGA_SR_STRINGTOEVAL,
                         comm, &status);

****************************************************************************U*/
void PGAReceiveIndividual(PGAContext *ctx, int p, int pop, int source, int tag,
                          MPI_Comm comm, MPI_Status *status)
{
     MPI_Datatype individualtype;

    PGADebugEntered("PGAReceiveIndividual");

     individualtype = PGABuildDatatype(ctx, p, pop);
     MPI_Recv(MPI_BOTTOM, 1, individualtype, source, tag, comm, status);
     MPI_Type_free(&individualtype);

    PGADebugExited("PGAReceiveIndividual");
}

/*U****************************************************************************
  PGASendReceiveIndividual - Send an individual to a process, while receiving
  a different individual from a different process.

  Category: Parallel

  Inputs:
    ctx       - context variable
    send_p    - index of string to send
    send_pop  - symbolic constant of population to send from
    dest      - destination process
    send_tag  - tag to send with
    recv_p    - index of string to receive
    recv_pop  - symbolic constant of population to receive from
    source    - process to receive from
    recv_tag  - tag to receive with
    comm      - an MPI communicator
    status    - pointer to the MPI status structure

  Outputs:
    status and string recv_p in population recv_pop are modified by
    side-effect.

  Example:
    A dedicated process is being used to perform an optimization algorithm
    on the strings.  Send a new string, s, to the process, while receiving an
    optimized string, r, from it.

    PGAContext *ctx;
    MPI_Comm    comm;
    MPI_Status  status;
    int  s, r;
    :
    PGASendReceiveIndividual(ctx, s, PGA_NEWPOP, 1, PGA_SR_STRINGTOMODIFY,
                                  r, PGA_NEWPOP, 1, PGA_SR_MODIFIEDSTRING,
                                  comm, &status);

****************************************************************************U*/
void PGASendReceiveIndividual(PGAContext *ctx, int send_p, int send_pop,
                              int dest, int send_tag, int recv_p, int recv_pop,
                              int source, int recv_tag, MPI_Comm comm,
                              MPI_Status *status)
{
     MPI_Datatype individualsendtype;
     MPI_Datatype individualrecvtype;

    PGADebugEntered("PGASendReceiveIndividual");

     individualsendtype = PGABuildDatatype(ctx, send_p, send_pop);
     individualrecvtype = PGABuildDatatype(ctx, recv_p, recv_pop);

     MPI_Sendrecv(MPI_BOTTOM, 1, individualsendtype, dest,   send_tag,
                  MPI_BOTTOM, 1, individualrecvtype, source, recv_tag,
                  comm, status);

     MPI_Type_free(&individualsendtype);
     MPI_Type_free(&individualrecvtype);

    PGADebugExited("PGASendReceiveIndividual");
}


/*I****************************************************************************
  PGARunIM - Execute the island model genetic algorithm

  Category: Parallel

  Inputs:
    ctx      - context variable
    evaluate - a pointer to the user's evaluation function, which must
               have the calling sequence shown in the example.
    comm     - the MPI communicator to use

  Outputs:
    none

  Example:
    PGAContext *ctx,
    double f(PGAContext *ctx, int p, int pop);
    MPI_Comm comm;
    :
    PGARunIM(ctx, f, comm);

****************************************************************************I*/
void PGARunIM(PGAContext *ctx, double (*f)(PGAContext *c, int p, int pop),
              MPI_Comm tcomm)
{
    /* Based on ctx->par.topology this routine will need to create the
       appropriate communicator out of tcomm
    */
    
     PGADebugEntered("PGARunIM");
     PGAError (ctx, "PGARunIM: Island model not implemented",
               PGA_FATAL, PGA_VOID, NULL);
     PGADebugExited("PGARunIM");
}


/*I****************************************************************************
  PGARunNM - Execute a neighborhood model genetic algorithm

  Category: Parallel

  Inputs:
    ctx      - context variable
    evaluate - a pointer to the user's evaluation function, which must
               have the calling sequence shown in the example.
    comm     - the MPI communicator to use

  Outputs:
    none

  Example:
    PGAContext *ctx,
    MPI_Comm comm;
    double f(PGAContext *ctx, int p, int pop);
    :
    PGARunNM(ctx, f, comm);

****************************************************************************I*/
void PGARunNM(PGAContext *ctx, double (*f)(PGAContext *c, int p, int pop),
              MPI_Comm tcomm)
{
    /* Based on ctx->par.topology this routine will need to create the
       appropriate communicator out of tcomm
    */
     PGADebugEntered("PGARunNM");
     PGAError (ctx, "PGARunNM: Island model not implemented",
               PGA_FATAL, PGA_VOID, NULL);
     PGADebugExited("PGARunNM");
}



/*U****************************************************************************
  PGAGetRank - Returns the rank of the processor in communicator comm.  If
  comm is NULL or a sequential version of PGAPack is used, PGAGetRank()
  returns 0.

  Category: Parallel

  Inputs:
      ctx  - context variable structure pointer
      comm - an MPI communicator

  Outputs:
      The rank of this processor

  Example:
      PGAContext  *ctx;
      int          rank;
      :
      rank = PGAGetRank(ctx, MPI_COMM_WORLD);
      if (rank == 0) {
          LetTheMasterDoSomething();
      }

****************************************************************************U*/
int PGAGetRank (PGAContext *ctx, MPI_Comm comm)
{
    int rank;
    
    PGADebugEntered("PGAGetRank");

    if (comm == NULL)
	rank = 0;
    else
	MPI_Comm_rank(comm, &rank);
    
    PGADebugExited("PGAGetRank");
    
    return(rank);
}


/*U****************************************************************************
  PGAGetNumProcs - Returns the size of communicator comm in processes.  If
  comm is NULL or a sequential version of PGAPack is used, PGAGetNumProcs()
  returns 1.

  Category: Parallel

  Inputs:
      ctx  - context variable structure pointer
      comm - an MPI communicator

  Outputs:
      The numbers of processors in communicator comm.

  Example:
      PGAContext  *ctx;
      :
      if (PGAGetNumProcs(ctx, MPI_COMM_WORLD) < 4) {
          printf("Too few processors for decent performance!\n");
	  exit(-1);
      }

****************************************************************************U*/
int PGAGetNumProcs (PGAContext *ctx, MPI_Comm comm)
{
    int size;

    PGADebugEntered("PGAGetNumProcs");

    if (comm == NULL)
	size = 1;
    else
	MPI_Comm_size(comm, &size);

    PGADebugExited("PGAGetNumProcs");

    return(size);
}


/*I****************************************************************************
   PGASetNumIslands - Set the number of islands to use in an island model
   GA. The default is one.  Currently must be the same as the number of
   processes in the default communicator.  

   Category: Parallel

   Inputs:
      ctx - context variable
      n   - number of islands

   Outputs:
      None

   Example:
      PGAContext *ctx,
      double f(PGAContext *ctx, int p, int pop);
      :
      ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
      PGASetNumIslands(ctx, 10);
      PGASetUp(ctx);
      PGARun(ctx, f);
      PGADestroy(ctx);

****************************************************************************I*/
void PGASetNumIslands( PGAContext *ctx, int n)
{

    PGADebugEntered("PGASetNumIslands");

    if ( n < 1 )
        PGAError(ctx, "PGASetNumIslands: Invalid value of n:",
                 PGA_FATAL, PGA_INT, (void *) &n);

    ctx->par.NumIslands = n;

    PGADebugExited("PGASetNumIslands");
}


/*I***************************************************************************
   PGAGetNumIslands - Returns the number of islands to use in an island model

   Category: Parallel

   Inputs:
      ctx - context variable

   Outputs:
       the number of islands to use in an island model

   Example:
      PGAContext *ctx;
      int npop;
      :
      npop = PGAGetNumIslands(ctx);

***************************************************************************I*/
int PGAGetNumIslands (PGAContext *ctx)
{
    PGADebugEntered("PGAGetNumIslands");
    PGAFailIfNotSetUp("PGAGetNumIslands");

    PGADebugExited("PGAGetNumIslands");

    return(ctx->par.NumIslands);
}

/*I****************************************************************************
   PGASetNumDemes - Set the number of demes to use in a neighborhood model
   GA. Currently must be the same as the number of processes in the default
   communicator.  The default is one.

   Category: Parallel

   Inputs:
      ctx          - context variable
      numdemes     - number of demes

   Outputs:
      None

   Example:
      PGAContext *ctx,
      double f(PGAContext *ctx, int p, int pop);
      :
      ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
      PGASetNumDemes(ctx, 4);
      PGASetUp(ctx);
      PGARun(ctx, f);
      PGADestroy(ctx);

****************************************************************************I*/
void PGASetNumDemes( PGAContext *ctx, int numdemes)
{
    PGADebugEntered("PGASetNumDemes");

    if ( numdemes < 1 )
        PGAError(ctx, "PGASetNumDemes: Invalid value of numdemes:",
                 PGA_FATAL, PGA_INT, (void *) &numdemes);

    ctx->par.NumDemes = numdemes;

    PGADebugExited("PGASetNumDemes");
}


/*I***************************************************************************
   PGAGetNumDemes - Returns the number of demes to use in a neighborhood model

   Category: Parallel

   Inputs:
      ctx - context variable

   Outputs:
       the number of demes to use in a neighborhood model

   Example:
      PGAContext *ctx;
      int npop;
      :
      npop = PGAGetNumDemes(ctx);

***************************************************************************I*/
int PGAGetNumDemes (PGAContext *ctx)
{
    PGADebugEntered("PGAGetNumDemes");
    PGAFailIfNotSetUp("PGAGetNumDemes");

    PGADebugExited("PGAGetNumDemes");

    return(ctx->par.NumDemes);
}


/*U****************************************************************************
   PGASetCommunicator - Set the default communicator to use when PGARun is
   called.  Does not necessarily need to be the same as the number of
   processes in MPI_COMM_WORLD (which is the default).

   Category: Parallel

   Inputs:
      ctx    - context variable
      comm   - communicator to use

   Outputs:
      None

   Example:
      MPI_Comm mycomm;
      PGAContext *ctx,
      double f(PGAContext *ctx, int p, int pop);
      :
      ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
      PGASetCommunicator(ctx, mycomm);
      PGASetUp(ctx);
      PGARun(ctx, f);
      PGADestroy(ctx);

****************************************************************************U*/
void PGASetCommunicator( PGAContext *ctx, MPI_Comm comm)
{

    PGADebugEntered("PGASetCommunicator");

    ctx->par.DefaultComm = comm;

    PGADebugExited("PGASetCommunicator");
}


/*U****************************************************************************
   PGAGetCommunicator - Returns the default communicator used when PGARun is
   called.
   
   Category: Parallel

   Inputs:
      ctx    - context variable

   Outputs:
      The default communicator

   Example:
      MPI_Comm comm;
      PGAContext *ctx,
      double f(PGAContext *ctx, int p, int pop);
      :
      ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
      PGASetUp(ctx);
      comm = PGAGetCommunicator(ctx);


****************************************************************************U*/
MPI_Comm PGAGetCommunicator( PGAContext *ctx)
{

    PGADebugEntered("PGAGetCommunicator");

    PGADebugExited("PGAGetCommunicator");

    return(ctx->par.DefaultComm);
}
