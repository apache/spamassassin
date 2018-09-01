/*  These are the definitions to use our fake version of MPI in mpi_stub.c 
 *  Guaranteed only to make PGAPack compile and link without MPI, but should
 *  work from user C and fortran programs.
 *
 *  Some of these are from mpich's mpi.h, others are custom.
 *
 *  Author: Brian P. Walenz
 */
typedef void *  MPI_Comm;
typedef void *  MPI_Datatype;
typedef long    MPI_Aint;

typedef struct {
    int     MPI_SOURCE;
    int     MPI_TAG;
    int     MPI_ERROR;
} MPI_Status;

#define MPI_BYTE            (void *)NULL
#define MPI_CHAR            (void *)NULL
#define MPI_DOUBLE          (void *)NULL
#define MPI_FLOAT           (void *)NULL
#define MPI_INT             (void *)NULL
#define MPI_LONG            (void *)NULL
#define MPI_LONG_DOUBLE     (void *)NULL
#define MPI_PACKED          (void *)NULL
#define MPI_SHORT           (void *)NULL
#define MPI_UNSIGNED_CHAR   (void *)NULL
#define MPI_UNSIGNED        (void *)NULL
#define MPI_UNSIGNED_LONG   (void *)NULL
#define MPI_UNSIGNED_SHORT  (void *)NULL

#define MPI_COMM_WORLD      (void *)NULL
#define MPI_COMM_SELF       (void *)NULL

#define MPI_BOTTOM          (void *)0

#define MPI_PROC_NULL       (-1)
#define MPI_ANY_SOURCE      (-2)
#define MPI_ANY_TAG         (-1)

/*  Declare prototypes for the MPI functions.  */
int MPI_Address(void *, MPI_Aint *);
int MPI_Bcast(void *, int, MPI_Datatype, int, MPI_Comm);
int MPI_Comm_dup(MPI_Comm, MPI_Comm *);
int MPI_Comm_free(MPI_Comm *);
int MPI_Comm_rank(MPI_Comm, int *);
int MPI_Comm_size(MPI_Comm, int *);
int MPI_Finalize(void);
int MPI_Init(int *, char ***);
int MPI_Initialized(int *);
int MPI_Probe(int, int, MPI_Comm, MPI_Status *);
int MPI_Send(void *, int, MPI_Datatype, int, int, MPI_Comm);
int MPI_Recv(void *, int, MPI_Datatype, int, int, MPI_Comm, MPI_Status *);
int MPI_Sendrecv(void *, int, MPI_Datatype, int, int, void *, int,
	         MPI_Datatype, int, int, MPI_Comm, MPI_Status *);
int MPI_Type_commit(MPI_Datatype *);
int MPI_Type_free(MPI_Datatype *);
int MPI_Type_struct(int, int *, MPI_Aint *, MPI_Datatype *, MPI_Datatype *);
