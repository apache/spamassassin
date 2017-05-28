c     
c     This is a test program for PGAPack.  The objective is to maximize the
c     number of 1-bits in a chromosome.
c     

      include 'pgapackf.h'

      double precision NumberOfSetBits
      external         NumberOfSetBits
      
c     
c     user main program
c     
      integer ctx
      integer       ierror

      call MPI_Init(ierror)

      ctx = PGACreate(PGA_DATATYPE_BINARY, 256, PGA_MAXIMIZE)
      call PGASetRandomSeed(ctx, 1)

      call PGASetUp(ctx)
      call PGARun(ctx, NumberOfSetBits)
      call PGADestroy(ctx)

      call MPI_Finalize(ierror)

      stop
      end


c     
c     user defined evaluation function
c     ctx - contex variable
c     p   - chromosome index in population
c     pop - which population to refer to
c     
      double precision function NumberOfSetBits(ctx, p, pop) 
      include    'pgapackf.h'
      integer ctx
      integer     p, pop
      integer     i, nbits, stringlen

      stringlen = PGAGetStringLength(ctx)
      
      nbits = 0
      do i=1, stringlen
         if (PGAGetBinaryAllele(ctx, p, pop, i) .eq. 1) then
            nbits = nbits + 1
         endif
      enddo

      NumberOfSetBits = dble(nbits)
      return
      end
