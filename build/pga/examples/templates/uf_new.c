/*  Stub functions for using PGAPAck with a user datatype.
 *
 *  Simple example (with no actual code) that shows how one would go about
 *  setting PGAPack up to evolve "strings" that are a single structure,
 *  using the necessary user defined functions.
 */
#include <pgapack.h>

void         MyCreateString(PGAContext *ctx, int p, int pop, int InitFlag);
MPI_Datatype MyBuildDatatype(PGAContext *ctx, int p, int pop);
int          MyMutation(PGAContext *ctx, int p, int pop, double mr);
void         MyCrossover(PGAContext *ctx, int p1, int p2, int p_pop, int c1,
	                 int c2, int c_pop);
void         MyPrintString(PGAContext *ctx, FILE *fp, int p, int pop);
void         MyCopyString(PGAContext *ctx, int p1, int pop1, int p2, int pop2);
int          MyDuplicateString(PGAContext *ctx, int p1, int pop1, int p2,
	                       int pop2);


double       MyEvaluate(PGAContext *ctx, int p, int pop);


typedef struct {
    /*  Put your favorite structure here!  */
} MyStruct;


int main(int argc, char **argv) {
  PGAContext *ctx;

  ctx = PGACreate(&argc, argv, PGA_DATATYPE_USER, 1, PGA_MAXIMIZE);

  PGASetUserFunction(ctx, PGA_USERFUNCTION_CREATESTRING,    MyCreateString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_BUILDDATATYPE,   MyBuildDatatype);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,        MyMutation);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,       MyCrossover);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING,     MyPrintString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_COPYSTRING,      MyCopyString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,       MyDuplicateString);

  PGASetUp(ctx);
  PGARun(ctx, MyEvaluate);
  PGADestroy(ctx);
  return(0);
}


/*  Function must allocate space for the "string", and, if InitFlag it PGA_TRUE,
 *  randomly initialize the string, otherwise, set it to zero.  Note that we
 *  do not need to keep track of each member of the population; the pointers
 *  are stored internally.
 */
void MyCreateString(PGAContext *ctx, int p, int pop, int InitFlag) {
  PGAIndividual  *New;
  MyStruct       *Data;

  New = PGAGetIndividual(ctx, p, pop);

  /*  Allocate space for the new chromosome.  */
  if (!(New->chrom = malloc(sizeof(MyStruct)))) {
    fprintf(stderr, "No more room in memory for the population!/n");
    exit(10);
  }

  /*  For convenience.  */
  Data = (MyStruct *)New->chrom;

  /*  Initialize, if needed.  Otherwise, clear.  */
}


/*  Perform mutation on a "string".  It is important to keep count of the 
 *  number of mutations performed and to return that value.
 */
int MyMutation(PGAContext *ctx, int p, int pop, double mr) {
  MyStruct   *Data;
  int         count;

  Data = (MyStruct *)PGAGetIndividual(ctx, p, pop)->chrom;

  /*  Insert code to mutate Data here.  Remember to count the number
   *  of mutations that happen, and return that value!
   */

  return(count);
}


/*  Perform crossover from two parents to two children.  */
void MyCrossover(PGAContext *ctx, int p1, int p2, int p_pop, int c1, int c2,
		 int c_pop) {
    MyStruct   *P1, *P2, *C1, *C2;

    P1 = (MyStruct *)PGAGetIndividual(ctx, p1, p_pop)->chrom;
    P2 = (MyStruct *)PGAGetIndividual(ctx, p2, p_pop)->chrom;
    C1 = (MyStruct *)PGAGetIndividual(ctx, c1, c_pop)->chrom;
    C2 = (MyStruct *)PGAGetIndividual(ctx, c1, c_pop)->chrom;
    
    /*  Perform crossover from P1 and P2 into C1 and C2 here.  */
}


/*  Print a "string" to the file fp.  */
void MyPrintString(PGAContext *ctx, FILE *fp, int p, int pop) {
    MyStruct   *Data;

    Data = (MyStruct *)PGAGetIndividual(ctx, p, pop)->chrom;
    
    /*  Print the string Data to the file fp.  */
}


/*  Copy one string to another.  If contiguous data, usually a call to memcpy.  */
void MyCopyString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    MyStruct  *P1, *P2;

    P1 = (MyStruct *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    P2 = (MyStruct *)PGAGetIndividual(ctx, p2, pop2)->chrom;

    /*  Copy string P1 into string P2.  This can be as simple as doing
     *      memcpy(P2, P1, sizeof(MyStruct_s));
     */
}


/*  Determine if two strings are the same.  If so, return non-zero, otherwise
 *  return zero.  If contiguous data, usually a call to memcmp.
 */
int MyDuplicateString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    MyStruct  *P1, *P2;

    P1 = (MyStruct *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    P2 = (MyStruct *)PGAGetIndividual(ctx, p2, pop2)->chrom;

    /*  Compare strings P1 and P2 to see if they are different.  If they
     *  are, return non-zero; else, return 0.  This can be as simple as
     *      return(!memcmp(P1, P2, sizeof(MyStruct_s)));
     */
}


/*  Randomly initialize a string.  */
void MyInitString(PGAContext *ctx, int p, int pop) {
  MyStruct   *Data;

  Data = (MyStruct *)PGAGetIndividual(ctx, p, pop)->chrom;

  /*  Insert code to randomly initialize Data here.  */
}


/*  Create an MPI_Datatype for the "string".  */
MPI_Datatype MyBuildDatatype(PGAContext *ctx, int p, int pop) {
  MyStruct   *Data;

  Data = (MyStruct *)PGAGetIndividual(ctx, p, pop)->chrom;

  /*  Insert code to build an MPI datatype here.  */
}


/*  The evaluation function.    */
double MyEvaluate(PGAContext *ctx, int p, int pop) {
    MyStruct   *Data;

    Data = (MyStruct *)PGAGetIndividual(ctx, p, pop)->chrom;
    
    /*  Evaluate the string here, and return a double representing
     *  the quality of the solution.
     */
}

