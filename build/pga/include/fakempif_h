c     These are the definitions to use our fake version of MPI in mpi_stub.c 
c     Guaranteed only to make PGAPack compile and link without MPI, but should
c     work from user fortran program.
c 
c     Some are from mpich's mpif.h, others are custom.
c
c     Author: Brian P. Walenz
c 
      integer MPI_BYTE, MPI_CHARACTER, MPI_COMPLEX
      integer MPI_DOUBLE_PRECISION, MPI_INTEGER, MPI_REAL
      integer MPI_LOGICAL, MPI_PACKED
      parameter(MPI_BYTE=0, MPI_CHARACTER=0, MPI_COMPLEX=0)
      parameter(MPI_DOUBLE_PRECISION=0, MPI_INTEGER=0, MPI_REAL=0)
      parameter(MPI_LOGICAL=0, MPI_PACKED=0)
      
      integer MPI_COMM_WORLD, MPI_COMM_SELF, MPI_BOTTOM
      parameter (MPI_COMM_WORLD=0, MPI_COMM_SELF=0, MPI_BOTTOM=0)
      
      integer MPI_PROC_NULL, MPI_ANY_SOURCE, MPI_ANY_TAG
      parameter(MPI_PROC_NULL=0, MPI_ANY_SOURCE=(-2), MPI_ANY_TAG=(-1))
      
      integer MPI_SOURCE, MPI_TAG, MPI_ERROR
      parameter(MPI_SOURCE=2, MPI_TAG=3, MPI_ERROR=4)
      
      integer MPI_STATUS_SIZE
      parameter (MPI_STATUS_SIZE=4)

c     Functions
      external MPI_Address, MPI_Bcast, MPI_Comm_dup, MPI_Comm_free
      external MPI_Comm_rank, MPI_Comm_size, MPI_Finalize, MPI_Init
      external MPI_Initialized, MPI_Probe, MPI_Send, MPI_Recv
      external MPI_Sendrecv, MPI_Type_commit, MPI_Type_free
      external MPI_Type_struct

