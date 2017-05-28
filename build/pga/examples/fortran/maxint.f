c     
c     This is a test program for PGAPack.  The objective is to 
c     maximize each allele.  The evaluation function sums all allele
c     values.
c     

      include 'pgapackf.h'
      include 'mpif.h'

      double precision evaluate
      integer          myMutation
      integer          GetIntegerParameter
      external         GetIntegerParameter, evaluate, myMutation

c     
c     user main program
c     
      integer ctx
      integer    len, maxiter, ierror


      call MPI_Init(ierror)

      len     = GetIntegerParameter('String length?      ')
      maxiter = GetIntegerParameter('How many iterations?')

      ctx = PGACreate(PGA_DATATYPE_INTEGER, len, PGA_MAXIMIZE)

      call PGASetRandomSeed(ctx, 1)
      call PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,
     &     myMutation)
      call PGASetIntegerInitPermute(ctx, 1, len)

      call PGASetMaxGAIterValue(ctx, maxiter)
      call PGASetNumReplaceValue(ctx, 90)
      call PGASetMutationAndCrossoverFlag(ctx, PGA_TRUE)
      call PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE)

      call PGASetUp(ctx)

      call PGARun(ctx, evaluate)
      call PGADestroy(ctx)

      call MPI_Finalize(ierror)

      stop
      end

c     Custom mutation function.  Searches for an unset bit, 
c     then sets it.  Returns the number of bits that are changed.
c     
      integer function myMutation(ctx, p, pop, mr)
      include          'pgapackf.h'
      integer ctx, p, pop
      double precision  mr
      integer           stringlen, i, v, count

      stringlen = PGAGetStringLength(ctx)
      count     = 0

      do i=stringlen, 1, -1
         if (PGARandomFlip(ctx, mr) .eq. PGA_TRUE) then
	    v = PGARandomInterval(ctx, 1, stringlen)
            call PGASetIntegerAllele(ctx, p, pop, i, v)
	    count = count + 1
         endif
      enddo

      myMutation = count
      return
      end


      double precision function evaluate(ctx, p, pop)
      include  'pgapackf.h'
      integer ctx, p, pop
      integer   stringlen, i, sum


      stringlen = PGAGetStringLength(ctx)
      sum       = 0

      do i=stringlen, 1, -1
         sum = sum + PGAGetIntegerAllele(ctx, p, pop, i) 
      enddo

      evaluate = dble(sum)
      return
      end


c     Get an integer parameter from the user.  Since this is
c     typically a parallel program, we must only do I/O on the
c     "master" process -- process 0.  Once we read the parameter,
c     we broadcast it to all the other processes, then every 
c     process returns the correct value.
c     
      integer function GetIntegerParameter(query)
      include      'pgapackf.h'
      include      'mpif.h'
      character*20  query
      integer       rank, tmp, ierror

      call MPI_Comm_rank(MPI_COMM_WORLD, rank, ierror)
      if (rank .eq. 0) then
         print *, query
         read *, tmp
      endif
      call MPI_Bcast(tmp, 1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)

      GetIntegerParameter = tmp
      return
      end
