c     Miscelaneous test functions.
c
c     Rather than deal with parallel I/O, we just list the tests here:
c       1.  Griewank
c       2.  Rastrigin
c       3.  Schwefel
c
      include 'pgapackf.h'
      include 'mpif.h'

      double precision  griewank, rastrigin, schwefel
      external          griewank, rastrigin, schwefel
      
      integer           GetIntegerParameter
      external          GetIntegerParameter

      double precision  Lower(3), Upper(3)
      integer           NumCoords(3)
      common /data/     Lower, Upper, NumCoords

      integer ctx
      integer           testnum, maxiter, i, ierror
      double precision  l(20), u(20)

c
c                   user main program                              
c

      call MPI_Init(ierror)

c     Yes, it's ugly, but it does work...
      testnum = GetIntegerParameter('Which test? (1-Griewank, 2-Rastrigi
     &n, 3-Schwefel) ')
      maxiter = GetIntegerParameter('How many iterations?               
     &               ')

      do i=1, 20
         l(i) = Lower(testnum)
         u(i) = Upper(testnum)
      enddo

      ctx = PGACreate(PGA_DATATYPE_REAL, NumCoords(testnum),
     &                PGA_MINIMIZE)
    
      call PGASetRandomSeed(ctx, 1)

      call PGASetRealInitRange(ctx, l, u)
      call PGASetMaxGAIterValue(ctx, maxiter)
    
      call PGASetUp(ctx)

      if (testnum .eq. 1)    call PGARun(ctx, griewank)
      if (testnum .eq. 2)    call PGARun(ctx, rastrigin)
      if (testnum .eq. 3)    call PGARun(ctx, schwefel)

      call PGADestroy(ctx)
    
      call MPI_Finalize(ierror)

      stop
      end


      double precision function griewank(ctx, p, pop)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, len
      double precision  allele, sum, product

      sum = 0.
      product = 1.
      len = PGAGetStringLength(ctx)
      do i=1, len
         allele = PGAGetRealAllele(ctx, p, pop, i)
         sum = sum + (allele * allele / 4000.)
         product = product * dcos(allele / sqrt((dble(i))))
      enddo

      griewank = 1. + sum - product
      return
      end


      double precision function rastrigin(ctx, p, pop)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, len
      double precision  allele, sum

      sum = 0.
      len = PGAGetStringLength(ctx)
      do i=1, len
         allele = PGAGetRealAllele(ctx, p, pop, i)
         sum = sum + allele * allele - 10.d0 * 
     &        dcos(6.28318530718d0 * allele)
      enddo

      rastrigin = dble(len-1) + sum
      return
      end



      double precision function schwefel(ctx, p, pop)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, len
      double precision  allele, sum

      sum = 0.
      len = PGAGetStringLength(ctx)
      do i=1, len
         allele = PGAGetRealAllele(ctx, p, pop, i)
         sum = sum - allele * dsin(dsqrt(dabs(allele)))
      enddo
     
      schwefel = sum
      return
      end



c     Get an integer parameter from the user.  Since this is
c     typically a parallel program, we must only do I/O on the
c     "master" process -- process 0.  Once we read the parameter,
c     we broadcast it to all the other processes, then every 
c     process returns the correct value.
c     
      integer function GetIntegerParameter(query)
      include 'pgapackf.h'
      include 'mpif.h'
      character*52 query
      integer  rank, tmp, ierror

      call MPI_Comm_rank(MPI_COMM_WORLD, rank, ierror)
      if (rank .eq. 0) then
         print *, query
         read *, tmp
      endif
      call MPI_Bcast(tmp, 1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)

      GetIntegerParameter = tmp
      return
      end


      block data
      integer i
      double precision Lower(3), Upper(3)
      integer NumCoords(3)
      common /data/    Lower, Upper, NumCoords

      data (NumCoords(i), i=1,3) / 10, 20, 10 /
      data (Lower(i), i=1,3)     / -512.0, -5.12, -512.0 /
      data (Upper(i), i=1,3)     / 511.0, 5.11, 511.0 /

      end
