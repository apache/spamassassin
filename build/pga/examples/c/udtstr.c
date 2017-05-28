/*****************************************************************************
 * The chromosome in this example is a structure containing three doubles    *
 * representing a translation along each of the x-, y-, and z-axes; three    *
 * doubles representing a rotation about each the axes; and forty ints       *
 * representing an index to side chain rotations.  This is a simple          *
 * illustration of how to set up a molecular docking problem.                *
 *****************************************************************************/
#include <pgapack.h>

double       energy           (double *, int *);
double       Evaluate         (PGAContext *, int, int);
void         CreateString     (PGAContext *, int, int, int);
int          Mutation         (PGAContext *, int, int, double);
void         Crossover        (PGAContext *, int, int, int, int, int, int);
void         WriteString      (PGAContext *, FILE *, int, int);
void         CopyString       (PGAContext *, int, int, int, int);
int          DuplicateString  (PGAContext *, int, int, int, int);
MPI_Datatype BuildDT          (PGAContext *, int, int);

typedef struct {
    double t[6];          /* ligand translation and rotation */
    int    sc[40];        /* ligand sidechain rotations      */
} ligand;

int main(int argc, char **argv) {
    PGAContext *ctx;

    ctx = PGACreate(&argc, argv, PGA_DATATYPE_USER, 46, PGA_MINIMIZE);
    PGASetRandomSeed    (ctx, 1);
    PGASetMaxGAIterValue(ctx, 5000);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_CREATESTRING,  (void *)CreateString);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_MUTATION,      (void *)Mutation);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_CROSSOVER,     (void *)Crossover);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_PRINTSTRING,   (void *)WriteString);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_COPYSTRING,    (void *)CopyString);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_DUPLICATE,     (void *)DuplicateString);
    PGASetUserFunction  (ctx, PGA_USERFUNCTION_BUILDDATATYPE, (void *)BuildDT);
    PGASetUp            (ctx);
    PGARun              (ctx, Evaluate);
    PGADestroy          (ctx);
    return (0);
}


/*****************************************************************************
 * CreateString allocates and initializes a chromosome.  If InitFlag is      *
 * set to true, then it will randomly initialize the chromosome; otherwise,  *
 * it sets each double to 0.0 and each int to 0.                             *
 *****************************************************************************/
void CreateString(PGAContext *ctx, int p, int pop, int InitFlag) {
    int i;
    ligand *ligand_ptr;
    PGAIndividual *new;

    new = PGAGetIndividual(ctx, p, pop);
    if (!(new->chrom = malloc(sizeof(ligand)))) {
        fprintf(stderr, "No room for new->chrom");
        exit(1);
    }
    ligand_ptr = (ligand *)new->chrom;
    if (InitFlag) {
        for (i = 0; i < 3; i++)
            ligand_ptr->t[i] = PGARandom01(ctx, 0) * 20.0 - 10.0;
        for (i = 3; i < 6; i++)
            ligand_ptr->t[i] = PGARandom01(ctx, 0) * 6.28 - 3.14;
        for (i = 0; i < 40; i++)
            ligand_ptr->sc[i] = PGARandomInterval(ctx, -20, 20);
    } else {
        for (i = 0; i < 6; i++)
            ligand_ptr->t[i] = 0.0;
        for (i = 0; i < 40; i++)
            ligand_ptr->sc[i] = 0;
    }
}


/*****************************************************************************
 * Mutation performs mutation on a chromosome.  Each allele has a mr         *
 * probability of being changed.  Mutation here perturbs each double by one  *
 * tenth and each int by 1.                                                  *
 *****************************************************************************/
int Mutation(PGAContext *ctx, int p, int pop, double mr) {
    ligand *ligand_ptr;
    int i, count = 0;

    ligand_ptr = (ligand *)PGAGetIndividual(ctx, p, pop)->chrom;
    for (i = 0; i < 6; i++)
        if (PGARandomFlip(ctx, mr)) {
            if (PGARandomFlip(ctx, 0.5))
                ligand_ptr->t[i] += 0.1*ligand_ptr->t[i];
            else
                ligand_ptr->t[i] -= 0.1*ligand_ptr->t[i];
            count++;
        }
    for (i = 0; i < 40; i++)
        if (PGARandomFlip(ctx, mr)) {
            if (PGARandomFlip(ctx, 0.5))
                ligand_ptr->sc[i] += 1;
            else
                ligand_ptr->sc[i] -= 1;
            count++;
        }
    return (count);
}


/*****************************************************************************
 * Crossover implements uniform crossover on the chromosome.                 *
 *****************************************************************************/
void Crossover(PGAContext *ctx, int p1, int p2, int pop1, int t1, int t2,
               int pop2) {
    int i;
    ligand *parent1, *parent2, *child1, *child2;
    double pu;

    parent1 = (ligand *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    parent2 = (ligand *)PGAGetIndividual(ctx, p2, pop1)->chrom;
    child1  = (ligand *)PGAGetIndividual(ctx, t1, pop2)->chrom;
    child2  = (ligand *)PGAGetIndividual(ctx, t2, pop2)->chrom;

    pu = PGAGetUniformCrossoverProb(ctx);

    for (i = 0; i < 6; i++)
            if (PGARandomFlip(ctx, pu)) {
                child1->t[i] = parent1->t[i];
                child2->t[i] = parent2->t[i];
            } else {
                child1->t[i] = parent2->t[i];
                child2->t[i] = parent1->t[i];
            }
    for (i = 0; i < 40; i++)
            if (PGARandomFlip(ctx, pu)) {
                child1->sc[i] = parent1->sc[i];
                child2->sc[i] = parent2->sc[i];
            } else {
                child1->sc[i] = parent2->sc[i];
                child2->sc[i] = parent1->sc[i];
            }
}


/*****************************************************************************
 * WriteString sends a visual representation of the chromosome to the file   *
 * fp.                                                                       *
 *****************************************************************************/
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop) {
    ligand *ligand_ptr;
    int i;

    ligand_ptr = (ligand *)PGAGetIndividual(ctx, p, pop)->chrom;
    
    fprintf(fp, "Position: [%11.7g, %11.7g, %11.7g]\n", 
	    ligand_ptr->t[0], ligand_ptr->t[1], ligand_ptr->t[2]);
    fprintf(fp, "Rotation: [%11.7g, %11.7g, %11.7g]\n", 
	    ligand_ptr->t[3], ligand_ptr->t[4], ligand_ptr->t[5]);

    fprintf(fp, "Sidechains:\n");
    for (i=0; i<40; i+=8) {
	fprintf(fp,"%2d: [%4ld] [%4ld] [%4ld] [%4ld]"
		       " [%4ld] [%4ld] [%4ld] [%4ld]\n", i, 
		ligand_ptr->sc[i+0], ligand_ptr->sc[i+2], 
		ligand_ptr->sc[i+2], ligand_ptr->sc[i+3], 
		ligand_ptr->sc[i+4], ligand_ptr->sc[i+5], 
		ligand_ptr->sc[i+6], ligand_ptr->sc[i+7]);
    }

    fprintf ( fp, "\n" );
}


/*****************************************************************************
 * CopyString makes a copy of the chromosome at (p1, pop1) and puts it at    *
 * (p2, pop2).                                                               *
 *****************************************************************************/
void CopyString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *d, *s;

     s = PGAGetIndividual(ctx, p1, pop1)->chrom;
     d = PGAGetIndividual(ctx, p2, pop2)->chrom;
     memcpy(d, s, sizeof(ligand));
}


/*****************************************************************************
 * DuplicateString compares two chromosomes and returns 1 if they are the    *
 * same and 0 if they are different.                                         *
 *****************************************************************************/
int DuplicateString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *a, *b;

     a = PGAGetIndividual(ctx, p1, pop1)->chrom;
     b = PGAGetIndividual(ctx, p2, pop2)->chrom;
     return (!memcmp(a, b, sizeof(ligand)));
}


/*****************************************************************************
 * BuildDatattype builds an MPI datatype for sending strings to other        *
 * processors.  Consult your favorite MPI manual for more information.       *
 *****************************************************************************/
MPI_Datatype BuildDT(PGAContext *ctx, int p, int pop) {
  int             counts[5];
  MPI_Aint        displs[5];
  MPI_Datatype    types[5];
  MPI_Datatype    DT_PGAIndividual;
  PGAIndividual  *P;
  ligand         *S;

  P = PGAGetIndividual(ctx, p, pop);
  S = (ligand *)P->chrom;

  /*  Build the MPI datatype.  Every user defined function needs these.
   *  The first two calls are stuff that is internal to PGAPack, but 
   *  the user still must include it.  See pgapack.h for details one the
   *  fields (under PGAIndividual)
   */
  MPI_Address(&P->evalfunc, &displs[0]);
  counts[0] = 2;
  types[0]  = MPI_DOUBLE;

  /*  Next, we have an integer, evaluptodate.  */  
  MPI_Address(&P->evaluptodate, &displs[1]);
  counts[1] = 1;
  types[1]  = MPI_INT;

  /*  Finally, we have the actual user-defined string.  */
  MPI_Address(S->t, &displs[2]);
  counts[2] = 6;
  types[2]  = MPI_DOUBLE;

  MPI_Address(S->sc, &displs[3]);
  counts[3] = 40;
  types[3]  = MPI_INT;

  MPI_Type_struct(4, counts, displs, types, &DT_PGAIndividual);
  MPI_Type_commit(&DT_PGAIndividual);
  return(DT_PGAIndividual);
}



double Evaluate(PGAContext *ctx, int p, int pop) {
    int     i;
    double  x[6];
    int     sc[40];
    ligand *lig;

    lig = (ligand *)PGAGetIndividual(ctx, p, pop)->chrom;
    for (i = 0; i < 6; i++)
        x[i] = lig->t[i];
    for (i = 0; i < 40; i++)
        sc[i] = lig->sc[i];
    return ( energy(x,sc) );
}


#define SQ(z)  ((z)*(z))

/*  For now just return distance from some fixed point plus
 *  a penalty for not being aligned to the x, y and z axes.
 *  The angles are divided by two so that we are in a range
 *  that only has one zero.
 */
double energy(double *x, int *sc) {
    double d;

    d = sqrt( SQ(x[0]-1) + SQ(x[1]-2) + SQ(x[2]-3)) +
	SQ(sin(x[3]/2)) + SQ(sin(x[4]/2)) + SQ(sin(x[5]/2));

    return (d);
}
