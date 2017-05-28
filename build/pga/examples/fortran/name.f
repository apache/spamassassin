c  PGAPack test program.
c
c  The objective is to evolve a string of characters to match a string
c  supplied by the user.  We will stop evolving when either we run out
c  of iterations (500), or when the best string has the same evaluation
c  value for 100 generations.
c
c  One problem with this implementation is that ' ' is not in
c  PGA_DATATYPE_CHAR if we limit it using PGA_CINIT_MIXED, PGA_CINIT_LOWER,
c  or PGA_CINIT_UPPER.  To fix this, we must define our own interval, and
c  thus, our own mutation, initialization operators.
c
c  A user function is also used to check the "done" condition; we are 
c  done if we've done more than 1000 iterations, or the evolved string
c  is correct.
c
c  Created 28 Sep 95, Brian P. Walenz.  Thanks to Dan Ashlock for the idea.
c
      include 'pgapackf.h'

      

      integer          N_Mutation
      integer          N_StopCond
      double precision EvalName
      
      external   N_Mutation
      external   N_StopCond
      external   EvalName
      external   N_InitString


c     I'm not claiming to be a FORTRAN hacker, so if you want to use
c     a string other than what is supplied, you must change the lengths 
c     to correspond to the length of the new string.
c     Also, this is common, sunce we need it in EvalName.
      character*33     Name
      common /global/  Name

      integer ctx
      integer    ierror


      call MPI_Init(ierror)

c             123456789012345678901234567890123
      Name = 'Levine, Hallstrom, Noelle, Walenz'

      ctx = PGACreate(PGA_DATATYPE_CHARACTER, 33, PGA_MAXIMIZE)
    
      call PGASetRandomSeed(ctx, 1)
    
      call PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING,
     &     N_InitString)
      call PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,
     &     N_Mutation)
      call PGASetUserFunction(ctx, PGA_USERFUNCTION_STOPCOND,
     &     N_StopCond)

      call PGASetPopSize(ctx, 100)
      call PGASetNumReplaceValue(ctx, 75)
      call PGASetPopReplaceType(ctx, PGA_POPREPL_BEST)
    
      call PGASetCrossoverProb(ctx, 0.0d0)
      call PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE)
    
      call PGASetMaxGAIterValue(ctx, 100)
    
      call PGASetUp(ctx)
      call PGARun(ctx, EvalName)
      call PGADestroy(ctx)

      call MPI_Finalize(ierror)

      stop
      end


c     Function to randomly initialize a PGA_DATATYPE_CHARACTER string 
c     using all printable ASCII characters for the range.
c
      subroutine N_InitString(ctx, p, pop) 
      include    'pgapackf.h'
      integer ctx
      integer     p, pop, i
    
      do i=1, PGAGetStringLength(ctx)
         call PGASetCharacterAllele(ctx, p, pop, i,
     &        char(PGARandomInterval(ctx, 32, 126)))
      enddo

      return
      end

c     Function to muatate a PGA_DATATYPE_CHARACTER string.  This is 
c     done by simply picking allele locations, and replacing whatever 
c     was there with a new value.  Again, legal values are all
c     printable ASCII characters.
c
      integer function N_Mutation(ctx, p, pop, mr)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, count
      double precision  mr

      count = 0

      do i=1, PGAGetStringLength(ctx)
         if (PGARandomFlip(ctx, mr) .eq. PGA_TRUE) then
            call PGASetCharacterAllele(ctx, p, pop, i,
     &           char(PGARandomInterval(ctx, 32, 126)))
            count = count + 1
         endif
      enddo
           
      N_Mutation = count
      return
      end



      integer function N_StopCond(ctx) 
      include   'pgapackf.h'
      include   'mpif.h'
      integer ctx
      integer    done, best


      done = PGACheckStoppingConditions(ctx, MPI_COMM_WORLD)
      best = PGAGetBestIndex(ctx, PGA_OLDPOP)
      if ((done .eq. PGA_FALSE) .and. 
     &     (PGAGetEvaluation(ctx, best, PGA_OLDPOP) .eq.
     &      PGAGetStringLength(ctx))) then
         done = PGA_TRUE
      endif

      N_StopCond = done
      return
      end

    
c     Evaluate the string.  A highly fit string will have many of
c     the characters matching Name.
c
      double precision function EvalName(ctx, p, pop)
      include          'pgapackf.h'
      integer ctx
      integer           p, pop, i, count
      character         Name(33)
      common /global/   Name
    
      count = 0
      do i=PGAGetStringLength(ctx), 1, -1
         if (PGAGetCharacterAllele(ctx, p, pop, i) .eq. Name(i)) then
            count = count + 1
         endif
      enddo

      EvalName = dble(count)
      return
      end
