      include 'pgapackf.h'

      double precision evaluate
      integer          myMutation
      external         evaluate, myMutation
      
      integer ctx
      integer          i, ierror
      integer          lower(10), upper(10)

      do i=1, 10
         lower(i) = 1
         upper(i) = 10
      enddo

      call MPI_Init(ierror)

      ctx = PGACreate         (PGA_DATATYPE_INTEGER, 10, PGA_MAXIMIZE)
      call PGASetUserFunction (ctx, PGA_USERFUNCTION_MUTATION,
     &                         myMutation)
      call PGASetIntegerInitRange(ctx, lower, upper)
      call PGASetUp              (ctx)
      call PGARun                (ctx, evaluate)
      call PGADestroy            (ctx)

      call MPI_Finalize(ierror)

      stop
      end


      integer function myMutation(ctx, p, pop, pm)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop
      double precision  pm
      integer           stringlen, i, k, count

      count = 0
      stringlen = PGAGetStringLength(ctx)
      do i=1, stringlen
         if (PGARandomFlip(ctx, pm) .eq. PGA_TRUE) then
            k = PGARandomInterval(ctx, 1, stringlen)
            call PGASetIntegerAllele(ctx, p, pop, i, k)
            count = count + 1
         endif
      enddo
      myMutation = count
      return
      end


      double precision function evaluate(ctx, p, pop)
      include          'pgapackf.h'
      integer ctx
      integer          p, pop
      integer          stringlen, i, sum

      sum = 0
      stringlen = PGAGetStringLength(ctx)
      do i=1, stringlen
         sum = sum + PGAGetIntegerAllele(ctx, p, pop, i)
      enddo
      evaluate = sum
      return
      end
