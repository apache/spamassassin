/*  Stub functions for using PGAPack with a native datatype, but user defined
 *  operators.
 *
 *  Simple example (with no actual code) that shows how one would go about
 *  setting PGAPack up to evolve "strings" that use a native datatype, but
 *  need to use custom evolutionary operators.
 */
#include <pgapack.h>

void         MyInitString(PGAContext *ctx, int p, int pop);
void         MyCrossover(PGAContext *ctx, int p1, int p2, int p_pop, int c1,
	                 int c2, int c_pop);
int          MyMutation(PGAContext *ctx, int p, int pop, double mr);
int          MyDuplicateString(PGAContext *ctx, int p1, int pop1, int p2,
	                       int pop2);
void         MyPrintString(PGAContext *ctx, FILE *fp, int p, int pop);
int          MyDone(PGAContext *ctx);
void         MyEndOfGen(PGAContext *ctx);

double       MyEvaluate(PGAContext *ctx, int p, int pop);
 

int main(int argc, char **argv) {
  PGAContext *ctx;

  ctx = PGACreate(&argc, argv, PGA_DATATYPE, 1, PGA_MAXIMIZE);

  PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,    MyMutation);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,   MyCrossover);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, MyPrintString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,   MyDuplicateString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING,  MyInitString);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_DONE,        MyDone);
  PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,    MyEndOfGen);
  
  PGASetUp(ctx);
  PGARun(ctx, MyEvaluate);
  PGADestroy(ctx);
  return(0);
}


/*  Perform mutation on a "string".  It is important to keep count of the 
 *  number of mutations performed and to return that value.
 */
int MyMutation(PGAContext *ctx, int p, int pop, double mr) {
  int         count;

  /*  Insert code to mutate Data here.  Remember to count the number
   *  of mutations that happen, and return that value!
   */

  return(count);
}


/*  Perform crossover from two parents to two children.  */
void MyCrossover(PGAContext *ctx, int p1, int p2, int p_pop, int c1, int c2,
		 int c_pop) {
    
    /*  Perform crossover from p1 and p2 into c1 and c2 here.  */
}


/*  Print a "string" to the file fp.  */
void MyPrintString(PGAContext *ctx, FILE *fp, int p, int pop) {

    /*  Print the string referenced by p and pop to the file fp.  */
}


/*  Determine if two strings are the same.  If so, return non-zero, otherwise
 *  return zero.  If contiguous data, usually a call to memcmp.
 */
int MyDuplicateString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {

    /*  Compare strings p1 and p2 to see if they are different.  If they
     *  are, return non-zero; else, return 0.
     */
}


/*  Randomly initialize a string.  */
void MyInitString(PGAContext *ctx, int p, int pop) {

  /*  Insert code to randomly initialize p in popultion pop here.  */
}


/*  Check if a GA has found an acceptable solution.  */
int MyDone(PGAContext *ctx) {
    int done = PGA_FALSE;

    /*  Check for "doneness".  */

    return(done);
}


/*  After each generation, this funciton will get called.  */
void MyEndOfGen(PGAContext *ctx) {

    /*  Do something useful; display the population on a graphics output,
     *  let the user adjust the population, etc.
     */
}


/*  The evaluation function.    */
double MyEvaluate(PGAContext *ctx, int p, int pop) {
    
    /*  Evaluate the string here, and return a double representing
     *  the quality of the solution.
     */
}

