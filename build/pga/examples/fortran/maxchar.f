c     Does not work, run it and see what happens.


c       
c     This is a test program for PGAPack.  The objective is to 
c     maximize the number of 'z's in a chromosome.
c       

      include 'pgapackf.h'
      include 'mpif.h'
      
      double precision NumberOfZs
      integer          myMutation
      integer          GetIntegerParameter
      external         NumberOfZs
      external         myMutation
      external         GetIntegerParameter
      
      integer ctx
      integer          len, maxiter, ierror
      
c     
c     user main program
c     
      call MPI_Init(ierror)
      
      len     = GetIntegerParameter('String length?      ')
      maxiter = GetIntegerParameter('How many iterations?')
      
      ctx     = PGACreate(PGA_DATATYPE_CHARACTER, len, PGA_MAXIMIZE)
      
      call PGASetRandomSeed(ctx, 1)
      call PGASetMaxGAIterValue(ctx, maxiter)
      call PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,
     &     myMutation)
      
      call PGASetUp(ctx)
      call PGARun(ctx, NumberOfZs)
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
      double precision function NumberOfZs(ctx, p, pop)
      include     'pgapackf.h'
      integer ctx
      integer      p, pop, i, nzs, stringlen
      
      stringlen = PGAGetStringLength(ctx)
      
      nzs = 0
      do i=1, stringlen
         if (PGAGetCharacterAllele(ctx, p, pop, i) .eq. 'z') then
            nzs = nzs + 1
         endif
      enddo
      
      NumberOfZs = dble(nzs)
      return
      end



c     Custom mutation function.  Searches for an unset bit, 
c     then sets it.  Returns the number of bits that are changed.
c     
      integer function myMutation(ctx, p, pop, mr)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, count
      character         c
      double precision  mr


      count = 0
      do i=PGAGetStringLength(ctx), 1, -1
         if (PGARandomFlip(ctx, mr) .eq. 1) then
            c = PGAGetCharacterAllele(ctx, p, pop, i)
            if (c .ne. 'z') then
               call PGASetCharacterAllele(ctx, p, pop, i,
     &              char(ichar(c)+1))
               count = count + 1
            endif
         endif
      enddo
      
      myMutation = count
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
      integer       rank, tmp

      call MPI_Comm_rank(MPI_COMM_WORLD, rank, ierror)
      if (rank .eq. 0) then
         print *, query
         read *, tmp
      endif
      call MPI_Bcast(tmp, 1, MPI_INTEGER, 0, MPI_COMM_WORLD, ierror)

      GetIntegerParameter = tmp
      return
      end
