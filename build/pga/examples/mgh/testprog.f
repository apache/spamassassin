      program mgh_testprobs

      include 'pgapackf.h'
      include 'mpif.h'

      external evaluate

      double precision evaluate
      integer ctx
      integer     len, nprob, maxiter, ierror, myid

      common nprob

      call MPI_INIT(ierror)
      call MPI_COMM_RANK(MPI_COMM_WORLD, myid, ierror)

      if (myid .EQ. 0) then
         print *, 'The following is a list of the test functions this pr
     &ogram supports.'
         print *, 'The number in parentheses after the name of the funct
     &ion is the'
         print *, 'dimension of the problem.  If the dimension is not a 
     &constant (i.e.,'
         print *, 'problems # 6-9, 13 - 15, and 18), the limitations on 
     &the dimension'
         print *, 'follow in parentheses after the function name.'

         print *
         print *, '1.  Helical Valley Function (3)'
         print *, '2.  Biggs EXP6 function (6)'
         print *, '3.  Gaussian Function (3)'
         print *, '4.  Powell Badly Scaled Function (2)'
         print *, '5.  Box Three-Dimensional Function (3)'
         print *, '6.  Variably-dimentioned Function (variable)'
         print *, '7.  Watson Function (2 - 31)'
         print *, '8.  Penalty function I (variable)'
         print *, '9.  Penalty function II (variable)'
         print *, '10.  Brown Badly Scaled Function (2)'
         print *, '11.  Brown and Dennis Function (4)'
         print *, '12.  Gulf Research And Development Function (3)'
         print *, '13.  Trigonometric Function (variable)'
         print *, '14.  Extended Rosenbrock Function (even)'
         print *, '15.  Extended Powell Singular Function (multiple of 4
     &)'
         print *, '16.  Beale Function (2)'
         print *, '17.  Wood Function (4)'
         print *, '18.  Chebyquad Function (variable less than 51)'
         print *
         print *, 'You will need to enter both the problem number and th
     &e dimension of the'
         print *, 'problem.  For problems with a constant dimension, use
     & the number in'
         print *, 'parenthesis.  For problems with variable dimension, m
     &ake sure the'
         print *, 'dimension that you choose falls within the stated lim
     &itations AND is'
         print *, 'less than or equal to 100.  For example, to select th
     &e Watson function'
         print *, 'with dimension twelve, enter the following: 7 12'
         print *
         print *, 'Please enter the problem number and dimension now.'
         read *, nprob, len
         if (nprob .LT. 1 .OR. nprob .GT. 18) then
            print *, 'Invalid problem number.'
            stop
         endif
         if (len .GT. 100) then
            print *, 'Dimension exceeds 100'
            stop
         endif
         print *, 'How many iterations? '
         read *, maxiter
      endif
      call MPI_BCAST(nprob,   1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)
      call MPI_BCAST(len,     1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)
      call MPI_BCAST(maxiter, 1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)
      ctx = PGACreate(PGA_DATATYPE_REAL, len, PGA_MINIMIZE)
      if (len .eq. 2) then
         call PGASetCrossoverType(ctx, PGA_CROSSOVER_UNIFORM)
      endif
      call PGASetMaxGAIterValue(ctx, maxiter)
      call PGASetPopSize(ctx, 10000)
      call PGASetRandomSeed(ctx, 1)
      call PGASetUp(ctx)
      call PGARun(ctx, evaluate)
      call PGADestroy(ctx)
      call MPI_FINALIZE(ierror)

      stop
      end


      double precision function evaluate(ctx, p, pop)
      include 'pgapackf.h'

      double precision x(100), f
      integer ctx
      integer    pop, p, i, stringlen, nprob

      common nprob

      stringlen = PGAGetStringLength(ctx)
      do i = 1, stringlen
         x(i) = PGAGetRealAllele(ctx, p, pop, i)
      enddo
      call objfcn(stringlen, x, f, nprob)
      evaluate = f

      return
      end
