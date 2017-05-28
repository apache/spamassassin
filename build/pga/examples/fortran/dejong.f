c  The DeJong test suite.
c
c

      include 'pgapackf.h'
      include 'mpif.h'

      double precision  dejong1, dejong2, dejong3, dejong4, dejong5
      external          dejong1, dejong2, dejong3, dejong4, dejong5

      integer           GetIntegerParameter
      external          GetIntegerParameter

      integer           gray_on
      integer           BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)

      common /data/     BinLen, NumCoords, Lower, Upper, gray_on

      integer ctx
      integer           testnum, maxiter, ierror


c
c                   user main program
c

      call MPI_Init(ierror)

      testnum = GetIntegerParameter('Which test? (1 - 5)        ')
      gray_on = GetIntegerParameter('Gray-coded? (1=yes, 0 = no)')
      maxiter = GetIntegerParameter('How many iterations?       ')

      ctx = PGACreate(PGA_DATATYPE_BINARY, 
     &     BinLen(testnum)*NumCoords(testnum), PGA_MINIMIZE)

      call PGASetMaxGAIterValue(ctx, maxiter)
      call PGASetRandomSeed(ctx, 1)
    
      call PGASetUp(ctx)

      if (testnum .eq. 1)    call PGARun(ctx, dejong1)
      if (testnum .eq. 2)    call PGARun(ctx, dejong2)
      if (testnum .eq. 3)    call PGARun(ctx, dejong3)
      if (testnum .eq. 4)    call PGARun(ctx, dejong4)
      if (testnum .eq. 5)    call PGARun(ctx, dejong5)

      call printResultInterpretation(ctx, testnum)

      call PGADestroy(ctx)
    
      call MPI_Finalize(ierror)

      stop
      end


      double precision function GetTerm(ctx, p, pop, t, problem) 
      include           'pgapackf.h'
      integer ctx
      integer            p, pop, t, problem, len
      integer            gray_on, BinLen(5), NumCoords(5)
      double precision   Lower(5), Upper(5)
      common /data/      BinLen, NumCoords, Lower, Upper, gray_on
      double precision   x, l, u

      len = BinLen(problem)
      l   = Lower(problem)
      u   = Upper(problem)

      if (gray_on .eq. 1) then
         x = PGAGetRealFromGrayCode(ctx, p, pop, (t-1)*len+1,
     &        t*len, l, u)
      else
         x = PGAGetRealFromBinary(ctx, p, pop, (t-1)*len+1, 
     &        t*len, l, u)
      endif

      GetTerm = x
      return
      end


      double precision function dejong1(ctx, p, pop) 
      include          'pgapackf.h'
      integer ctx
      integer           p, pop
      double precision  GetTerm
      external          GetTerm 
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      integer           i
      double precision  term, sum

      sum = 0.
    
      do i=1, NumCoords(1)
         term = GetTerm(ctx, p, pop, i, 1)
         sum = sum + (term * term)
      enddo
      
      dejong1 = sum
      return
      end


      double precision function dejong2(ctx, p, pop) 
      include          'pgapackf.h'
      integer ctx
      integer           p, pop
      double precision  GetTerm
      external          GetTerm
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      double precision  x1, x2, p1, p2
    
      x1 = GetTerm(ctx, p, pop, 1, 2)
      x2 = GetTerm(ctx, p, pop, 2, 2)
      p1 = x1 * x1 - x2
      p2 = 1 - x1

      dejong 2 = 100 * p1 * p1 + p2 * p2
      return
      end


      double precision function dejong3(ctx, p, pop) 
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i
      double precision  GetTerm
      external          GetTerm
      double precision  sum
      external          ffloor
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      double precision  ffloor

      sum = 0.
    
      do i=1, NumCoords(3)
         sum = sum + ffloor(GetTerm(ctx, p, pop, i, 3)) 
      enddo
         
      dejong3 = sum
      return
      end



      double precision function dejong4(ctx, p, pop) 
      include          'pgapackf.h'
      integer ctx
      integer           p, pop
      double precision  GetTerm
      external          GetTerm
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      integer           i
      double precision  term, sum
      
      sum = 0.
      do i=1, NumCoords(4)
         term = GetTerm(ctx, p, pop, i, 4)
         sum = sum + (i * term * term * term * term)
      enddo
    
      
      dejong4 = sum + PGARandomGaussian(ctx, 0d0, 1d0)
      return
      end


      double precision function dejong5(ctx, p, pop) 
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, j
      double precision  GetTerm
      external          GetTerm
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      double precision  a(2,25)
      double precision  sum_over_i, sum_over_j

      sum_over_i = 0.
      sum_over_j = 0.

      do i=0, 4
         a(1,5*i+1)   = -32.
         a(2,i+1)     = -32.
         
         a(1,5*i+2) = -16.
         a(2,i+6)   = -16.
         
         a(1,5*i+3) = 0.
         a(2,i+11)  = 0.
         
         a(1,5*i+4) = 16.
         a(2,i+16)  = 16.
         
         a(1,5*i+5) = 32.
         a(2,i+21)  = 32.
      enddo
      
      
      do j=1, 25
         sum_over_i =
     &        (GetTerm(ctx, p, pop, 1, 5) - a(1,j)) ** 6 +
     &        (GetTerm(ctx, p, pop, 2, 5) - a(2,j)) ** 6
         sum_over_j = sum_over_j + (1.0d0 / (dble(j-1) + sum_over_i))
      enddo
    
      dejong5 = 1.0d0 / (0.002d0 + sum_over_j)
      return
      end



c     Since the linker searches this file first, if this function were
c     called just "floor", PGAPack would break.  (PGAPack uses a floor
c     function also).
c
      double precision function ffloor(x)
      double precision  x, y

      y = int(x)
      if (x .lt. 0 .and. x .ne. y) then
         y = y - 1
      endif
      ffloor = y

      end





      subroutine printResultInterpretation(ctx, problem)
      include          'pgapackf.h'
      include          'mpif.h'
      integer ctx
      integer           problem, best, i
      double precision  GetTerm
      external          GetTerm
      integer           gray_on, BinLen(5), NumCoords(5)
      double precision  Lower(5), Upper(5)
      common /data/     BinLen, NumCoords, Lower, Upper, gray_on
      double precision  value
      integer comm


      comm = PGAGetCommunicator(ctx)
      if (PGAGetRank(ctx, comm) .eq. 0) then
c      if (PGAGetRank(ctx, MPI_COMM_WORLD) .eq. 0) then
         best = PGAGetBestIndex(ctx, PGA_OLDPOP)
	
         print *, 'The real interpretation:'
         do i=1, NumCoords(problem)
	    value = GetTerm(ctx, best, PGA_OLDPOP, i, problem)
	    
            print *, '#', i, ': ', value
         enddo

      endif

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
      character*27  query
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


      block data
      integer i
      double precision Lower(5), Upper(5)
      integer gray_on, BinLen(5), NumCoords(5)
      common /data/ BinLen, NumCoords, Lower, Upper, gray_on

      data (BinLen(i), i=1,5)    / 10, 12, 10, 8, 17 /
      data (NumCoords(i), i=1,5) / 3, 2, 5, 30, 2 /
      data (Lower(i), i=1,5)     / -5.12,-2.048,-5.12,-1.28,-65.536 /
      data (Upper(i), i=1,5)     / 5.11, 2.047, 5.11, 1.27, 65.535 /

      end
