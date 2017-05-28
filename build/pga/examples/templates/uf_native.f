c     Stub functions for using PGAPack with a natve datatype, but user
c     defined operators.
c
c     In Fortran, we cannot allocate memory, nor can we define a C type
c     structure, thus, userdefined data types are rather silly.  So,
c     PGA_USERFUNCTION_CREATESTRING, and PGA_USERFUNCTION_BUILDDATATYPE are
c     not allowed.

      include 'pgapackf.h'

      external MyInitString
      external MyCrossover
      external MyMutation
      external MyDuplicateString
      external MyPrintString
      external MyDone
      external MyEndOfGen
      external MyEvaluate

      integer          MyMutation
      integer          MyDuplicateString
      integer          MyDone
      double precision MyEvaluate

      integer ctx


      ctx = PGACreate(PGA_DATATYPE_INTEGER, 10, PGA_MAXIMIZE)

      PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,    MyMutation)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,   MyCrossover)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, MyPrintString)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,   MyDuplicateString)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING,  MyInitString)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_DONE,        MyDone)
      PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,    MyEndOfGen)
  
      PGASetUp(ctx)
      PGARun(ctx, MyEvaluate)
      PGADestroy(ctx)

      stop
      end





c     Perform mutation on a "string".  It is important to keep count of
c     the number of mutations performed and to return that value.
c
      integer function MyMutation(ctx, p, pop, mr)
      include 'pgapackf.h'
      integer ctx, p, pop, count, length
      double precision mr

      length = PGAGetStringLength(ctx)

      do i=1, length
         if (PGARandomFlip(ctx, mr) .eq. PGA_TRUE) then
c
c           Insert code to mutate an allele here.  Remember to count
c           the number of mutations that happen, and return that value!
c
         endif
      enddo

      MyMutation = count
      return
      end


c     Perform crossover from two parents to two children.  
      subroutine MyCrossover(ctx, p1, p2, p_pop, c1, c2, c_pop)
      include 'pgapackf.h'
      integer ctx, p1, p2, p_pop, c1, c2, c_pop

c     Perform crossover from P1 and P2 into C1 and C2 here. 

      return
      end
      



c     Print a "string".  The second argument is a C file pointer, 
c     but we cannot do anything with it,
      subroutine MyPrintString(ctx, fp, p, pop)
      include 'pgapackf.h'
      integer ctx, fp, p, pop
     
c     Print the string

      return
      end



c     Determine if two strings are the same.  If so, return non-zero,
c     otherwise return zero.
      integer function MyDuplicateString(ctx, p1, pop1, p2, pop2)
      include 'pgapackf.h'
      integer ctx, p1, pop1, p2, pop2, equal

c     Compare the strings

      MyDuplicateString = equal
      return
      end



c     Randomly initialize a string.
      subroutine MyInitString(ctx, p, pop)
      include 'pgapackf.h'
      integer ctx, p, pop

c     Insert code to randomly initialize Data here. 

      return
      end


c     Check if a GA has found an acceptable solution.
      integer function MyDone(ctx) 
      include 'pgapackf.h'
      integer ctx, done

      done = PGA_FALSE

c     Check for "doneness".

      MyDone = done
      return
      end


c     After each generation, this funciton will get called.
      subroutine MyEndOfGen(ctx)
      include 'pgapackf.h'
      integer ctx

c     Do something useful; display the population on a graphics output,
c     let the user adjust the population, etc.

      return
      end



c     The evaluation function.
      double precision function MyEvaluate(ctx, p, pop)
      include 'pgapackf.h'
      integer ctx, p, pop

c     Evaluate the string

      MyEvaluate = evaluation
      return
      end
