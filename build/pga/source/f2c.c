/*
COPYRIGHT

The following is a notice of limited availability of the code, and disclaimer
which must be included in the prologue of the code and in all source listings
of the code.

(C) COPYRIGHT 2008 University of Chicago

Permission is hereby granted to use, reproduce, prepare derivative works, and
to redistribute to others. This software was authored by:

D. Levine
Mathematics and Computer Science Division 
Argonne National Laboratory Group

with programming assistance of participants in Argonne National 
Laboratory's SERS program.

GOVERNMENT LICENSE

Portions of this material resulted from work developed under a
U.S. Government Contract and are subject to the following license: the
Government is granted for itself and others acting on its behalf a paid-up,
nonexclusive, irrevocable worldwide license in this computer software to
reproduce, prepare derivative works, and perform publicly and display
publicly.

DISCLAIMER

This computer code material was prepared, in part, as an account of work
sponsored by an agency of the United States Government. Neither the United
States, nor the University of Chicago, nor any of their employees, makes any
warranty express or implied, or assumes any legal liability or responsibility
for the accuracy, completeness, or usefulness of any information, apparatus,
product, or process disclosed, or represents that its use would not infringe
privately owned rights.
*/

/*****************************************************************************
*     FILE: f2c_interface.c
*
*     This file contains routines that are called by the Fortran version of
*     the PGAPack calls.  They just make the call to the appropriate C
*     routine.  Issues are:
*         * Fortran's always passing by reference,
*         * Using Fortran integers for holding C pointer values
*         * Fortran's 1,...,n indexing vs. C's 0,...,n-1
*           (this comes up in population member and allele indices)
*         * Pointers to functions
*         * File pointers
*         * Characters strings
*         * Variable length argument lists
*
*     We assume the Fortran compiler generates one of three symbol names for
*     the external PGAPack routine, e.g.,  pgasetpopsize,  pgasetpopsize_, or
*     PGASETPOPSIZE.  We use #ifdef's based on the appropriate routine to
*     convert the canonical pgasetpopsize_ to the other two.  Since the real
*     C routine is always mixed case we will never have a conflict.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

#if defined(FORTRANCAP)
#define pgasetbinaryallele_              PGASETBINARYALLELE
#define pgagetbinaryallele_              PGAGETBINARYALLELE
#define pgasetbinaryinitprob_            PGASETBINARYINITPROB
#define pgagetbinaryinitprob_            PGAGETBINARYINITPROB
#define pgasetcharacterallele_           PGASETCHARACTERALLELE
#define pgagetcharacterallele_           PGAGETCHARACTERALLELE
#define pgasetcharacterinittype_         PGASETCHARACTERINITTYPE
#define pgacreate_                       PGACREATE
#define pgasetup_                        PGASETUP
#define pgasetrandominitflag_            PGASETRANDOMINITFLAG
#define pgagetrandominitflag_            PGAGETRANDOMINITFLAG
#define pgacrossover_                    PGACROSSOVER
#define pgagetcrossovertype_             PGAGETCROSSOVERTYPE
#define pgagetcrossoverprob_             PGAGETCROSSOVERPROB
#define pgagetuniformcrossoverprob_      PGAGETUNIFORMCROSSOVERPROB
#define pgasetcrossovertype_             PGASETCROSSOVERTYPE
#define pgasetcrossoverprob_             PGASETCROSSOVERPROB
#define pgasetuniformcrossoverprob_      PGASETUNIFORMCROSSOVERPROB
#define pgadebugprint_                   PGADEBUGPRINT
#define pgasetdebuglevel_                PGASETDEBUGLEVEL
#define pgacleardebuglevel_              PGACLEARDEBUGLEVEL
#define pgasetdebuglevelbyname_          PGASETDEBUGLEVELBYNAME
#define pgacleardebuglevelbyname_        PGACLEARDEBUGLEVELBYNAME
#define pgaduplicate_                    PGADUPLICATE
#define pgachange_                       PGACHANGE
#define pgasetnoduplicatesflag_          PGASETNODUPLICATESFLAG
#define pgagetnoduplicatesflag_          PGAGETNODUPLICATESFLAG
#define pgasetevaluation_                PGASETEVALUATION
#define pgagetevaluation_                PGAGETEVALUATION
#define pgasetevaluationuptodateflag_    PGASETEVALUATIONUPTODATEFLAG
#define pgagetevaluationuptodateflag_    PGAGETEVALUATIONUPTODATEFLAG
#define pgagetrealfrombinary_            PGAGETREALFROMBINARY
#define pgagetrealfromgraycode_          PGAGETREALFROMGRAYCODE
#define pgaencoderealasbinary_           PGAENCODEREALASBINARY
#define pgaencoderealasgraycode_         PGAENCODEREALASGRAYCODE
#define pgagetintegerfrombinary_         PGAGETINTEGERFROMBINARY
#define pgagetintegerfromgraycode_       PGAGETINTEGERFROMGRAYCODE
#define pgaencodeintegerasbinary_        PGAENCODEINTEGERASBINARY
#define pgaencodeintegerasgraycode_      PGAENCODEINTEGERASGRAYCODE
#define pgafitness_                      PGAFITNESS
#define pgarank_                         PGARANK
#define pgagetfitness_                   PGAGETFITNESS
#define pgagetfitnesstype_               PGAGETFITNESSTYPE
#define pgagetfitnessmintype_            PGAGETFITNESSMINTYPE
#define pgagetmaxfitnessrank_            PGAGETMAXFITNESSRANK
#define pgasetfitnesstype_               PGASETFITNESSTYPE
#define pgasetfitnessmintype_            PGASETFITNESSMINTYPE
#define pgasetmaxfitnessrank_            PGASETMAXFITNESSRANK
#define pgasetfitnesscmaxvalue_          PGASETFITNESSCMAXVALUE
#define pgagetfitnesscmaxvalue_          PGAGETFITNESSCMAXVALUE
#define pgahammingdistance_              PGAHAMMINGDISTANCE
#define pgasetintegerallele_             PGASETINTEGERALLELE
#define pgagetintegerallele_             PGAGETINTEGERALLELE
#define pgasetintegerinitpermute_        PGASETINTEGERINITPERMUTE
#define pgasetintegerinitrange_          PGASETINTEGERINITRANGE
#define pgagetintegerinittype_           PGAGETINTEGERINITTYPE
#define pgagetminintegerinitvalue_       PGAGETMININTEGERINITVALUE
#define pgagetmaxintegerinitvalue_       PGAGETMAXINTEGERINITVALUE
#define pgamutate_                       PGAMUTATE
#define pgasetmutationtype_              PGASETMUTATIONTYPE
#define pgagetmutationtype_              PGAGETMUTATIONTYPE
#define pgasetmutationrealvalue_         PGASETMUTATIONREALVALUE
#define pgagetmutationrealvalue_         PGAGETMUTATIONREALVALUE
#define pgasetmutationintegervalue_      PGASETMUTATIONINTEGERVALUE
#define pgagetmutationintegervalue_      PGAGETMUTATIONINTEGERVALUE
#define pgasetmutationboundedflag_       PGASETMUTATIONBOUNDEDFLAG
#define pgagetmutationboundedflag_       PGAGETMUTATIONBOUNDEDFLAG
#define pgasetmutationprob_              PGASETMUTATIONPROB
#define pgagetmutationprob_              PGAGETMUTATIONPROB
#define pgarungm_                        PGARUNGM
#define pgaevaluate_                     PGAEVALUATE
#define pgabuilddatatype_                PGABUILDDATATYPE
#define pgasendindividual_               PGASENDINDIVIDUAL
#define pgareceiveindividual_            PGARECEIVEINDIVIDUAL
#define pgasendreceiveindividual_        PGASENDRECEIVEINDIVIDUAL
#define pgagetrank_                      PGAGETRANK
#define pgagetnumprocs_                  PGAGETNUMPROCS
#define pgasetcommunicator_              PGASETCOMMUNICATOR
#define pgagetcommunicator_              PGAGETCOMMUNICATOR
#define pgarun_                          PGARUN
#define pgarunmutationandcrossover_      PGARUNMUTATIONANDCROSSOVER
#define pgarunmutationorcrossover_       PGARUNMUTATIONORCROSSOVER
#define pgaupdategeneration_             PGAUPDATEGENERATION
#define pgagetdatatype_                  PGAGETDATATYPE
#define pgagetoptdirflag_                PGAGETOPTDIRFLAG
#define pgagetstringlength_              PGAGETSTRINGLENGTH
#define pgagetgaitervalue_               PGAGETGAITERVALUE
#define pgasetmutationorcrossoverflag_   PGASETMUTATIONORCROSSOVERFLAG
#define pgasetmutationandcrossoverflag_  PGASETMUTATIONANDCROSSOVERFLAG
#define pgagetmutationorcrossoverflag_   PGAGETMUTATIONORCROSSOVERFLAG
#define pgagetmutationandcrossoverflag_  PGAGETMUTATIONANDCROSSOVERFLAG
#define pgasortpop_                      PGASORTPOP
#define pgagetpopsize_                   PGAGETPOPSIZE
#define pgagetnumreplacevalue_           PGAGETNUMREPLACEVALUE
#define pgagetpopreplacetype_            PGAGETPOPREPLACETYPE
#define pgagetsortedpopindex_            PGAGETSORTEDPOPINDEX
#define pgasetpopsize_                   PGASETPOPSIZE
#define pgasetnumreplacevalue_           PGASETNUMREPLACEVALUE
#define pgasetpopreplacetype_            PGASETPOPREPLACETYPE
#define pgarandomflip_                   PGARANDOMFLIP
#define pgarandominterval_               PGARANDOMINTERVAL
#define pgarandom01_                     PGARANDOM01
#define pgarandomuniform_                PGARANDOMUNIFORM
#define pgarandomgaussian_               PGARANDOMGAUSSIAN
#define pgagetrandomseed_                PGAGETRANDOMSEED
#define pgasetrandomseed_                PGASETRANDOMSEED
#define pgasetrealallele_                PGASETREALALLELE
#define pgagetrealallele_                PGAGETREALALLELE
#define pgasetrealinitpercent_           PGASETREALINITPERCENT
#define pgasetrealinitrange_             PGASETREALINITRANGE
#define pgagetminrealinitvalue_          PGAGETMINREALINITVALUE
#define pgagetmaxrealinitvalue_          PGAGETMAXREALINITVALUE
#define pgagetrealinittype_              PGAGETREALINITTYPE
#define pgaprintreport_                  PGAPRINTREPORT
#define pgasetprintoptions_              PGASETPRINTOPTIONS
#define pgasetprintfrequencyvalue_       PGASETPRINTFREQUENCYVALUE
#define pgagetprintfrequencyvalue_       PGAGETPRINTFREQUENCYVALUE
#define pgaprintpopulation_              PGAPRINTPOPULATION
#define pgaprintindividual_              PGAPRINTINDIVIDUAL
#define pgaprintstring_                  PGAPRINTSTRING
#define pgaprintcontextvariable_         PGAPRINTCONTEXTVARIABLE
#define pgarestart_                      PGARESTART
#define pgasetrestartflag_               PGASETRESTARTFLAG
#define pgagetrestartflag_               PGAGETRESTARTFLAG
#define pgasetrestartfrequencyvalue_     PGASETRESTARTFREQUENCYVALUE
#define pgagetrestartfrequencyvalue_     PGAGETRESTARTFREQUENCYVALUE
#define pgasetrestartallelechangeprob_   PGASETRESTARTALLELECHANGEPROB
#define pgagetrestartallelechangeprob_   PGAGETRESTARTALLELECHANGEPROB
#define pgaselect_                       PGASELECT
#define pgaselectnextindex_              PGASELECTNEXTINDEX
#define pgasetselecttype_                PGASETSELECTTYPE
#define pgagetselecttype_                PGAGETSELECTTYPE
#define pgasetptournamentprob_           PGASETPTOURNAMENTPROB
#define pgagetptournamentprob_           PGAGETPTOURNAMENTPROB
#define pgadone_                         PGADONE
#define pgacheckstoppingconditions_      PGACHECKSTOPPINGCONDITIONS
#define pgasetstoppingruletype_          PGASETSTOPPINGRULETYPE
#define pgagetstoppingruletype_          PGAGETSTOPPINGRULETYPE
#define pgasetmaxgaitervalue_            PGASETMAXGAITERVALUE
#define pgagetmaxgaitervalue_            PGAGETMAXGAITERVALUE
#define pgasetmaxnochangevalue_          PGASETMAXNOCHANGEVALUE
#define pgasetmaxsimilarityvalue_        PGASETMAXSIMILARITYVALUE
#define pgaerror_                        PGAERROR
#define pgadestroy_                      PGADESTROY
#define pgagetmaxmachineintvalue_        PGAGETMAXMACHINEINTVALUE
#define pgagetminmachineintvalue_        PGAGETMINMACHINEINTVALUE
#define pgagetmaxmachinedoublevalue_     PGAGETMAXMACHINEDOUBLEVALUE
#define pgagetminmachinedoublevalue_     PGAGETMINMACHINEDOUBLEVALUE
#define pgausage_                        PGAUSAGE
#define pgaprintversionnumber_           PGAPRINTVERSIONNUMBER
#define pgasetuserfunction_              PGASETUSERFUNCTION
#define pgamean_                         PGAMEAN
#define pgastddev_                       PGASTDDEV
#define pgaround_                        PGAROUND
#define pgacopyindividual_               PGACOPYINDIVIDUAL
#define pgachecksum_                     PGACHECKSUM
#define pgagetworstindex_                PGAGETWORSTINDEX
#define pgagetbestindex_                 PGAGETBESTINDEX

#elif defined(FORTRANTWOUNDERSCORE)
#define pgasetbinaryallele_              _pgasetbinaryallele_
#define pgagetbinaryallele_              _pgagetbinaryallele_
#define pgasetbinaryinitprob_            _pgasetbinaryinitprob_
#define pgagetbinaryinitprob_            _pgagetbinaryinitprob_
#define pgasetcharacterallele_           _pgasetcharacterallele_
#define pgagetcharacterallele_           _pgagetcharacterallele_
#define pgasetcharacterinittype_         _pgasetcharacterinittype_
#define pgacreate_                       _pgacreate_
#define pgasetup_                        _pgasetup_
#define pgasetrandominitflag_            _pgasetrandominitflag_
#define pgagetrandominitflag_            _pgagetrandominitflag_
#define pgacrossover_                    _pgacrossover_
#define pgagetcrossovertype_             _pgagetcrossovertype_
#define pgagetcrossoverprob_             _pgagetcrossoverprob_
#define pgagetuniformcrossoverprob_      _pgagetuniformcrossoverprob_
#define pgasetcrossovertype_             _pgasetcrossovertype_
#define pgasetcrossoverprob_             _pgasetcrossoverprob_
#define pgasetuniformcrossoverprob_      _pgasetuniformcrossoverprob_
#define pgadebugprint_                   _pgadebugprint_
#define pgasetdebuglevel_                _pgasetdebuglevel_
#define pgacleardebuglevel_              _pgacleardebuglevel_
#define pgasetdebuglevelbyname_          _pgasetdebuglevelbyname_
#define pgacleardebuglevelbyname_        _pgacleardebuglevelbyname_
#define pgaduplicate_                    _pgaduplicate_
#define pgachange_                       _pgachange_
#define pgasetnoduplicatesflag_          _pgasetnoduplicatesflag_
#define pgagetnoduplicatesflag_          _pgagetnoduplicatesflag_
#define pgasetevaluation_                _pgasetevaluation_
#define pgagetevaluation_                _pgagetevaluation_
#define pgasetevaluationuptodateflag_    _pgasetevaluationuptodateflag_
#define pgagetevaluationuptodateflag_    _pgagetevaluationuptodateflag_
#define pgagetrealfrombinary_            _pgagetrealfrombinary_
#define pgagetrealfromgraycode_          _pgagetrealfromgraycode_
#define pgaencoderealasbinary_           _pgaencoderealasbinary_
#define pgaencoderealasgraycode_         _pgaencoderealasgraycode_
#define pgagetintegerfrombinary_         _pgagetintegerfrombinary_
#define pgagetintegerfromgraycode_       _pgagetintegerfromgraycode_
#define pgaencodeintegerasbinary_        _pgaencodeintegerasbinary_
#define pgaencodeintegerasgraycode_      _pgaencodeintegerasgraycode_
#define pgafitness_                      _pgafitness_
#define pgarank_                         _pgarank_
#define pgagetfitness_                   _pgagetfitness_
#define pgagetfitnesstype_               _pgagetfitnesstype_
#define pgagetfitnessmintype_            _pgagetfitnessmintype_
#define pgagetmaxfitnessrank_            _pgagetmaxfitnessrank_
#define pgasetfitnesstype_               _pgasetfitnesstype_
#define pgasetfitnessmintype_            _pgasetfitnessmintype_
#define pgasetmaxfitnessrank_            _pgasetmaxfitnessrank_
#define pgasetfitnesscmaxvalue_          _pgasetfitnesscmaxvalue_
#define pgagetfitnesscmaxvalue_          _pgagetfitnesscmaxvalue_
#define pgahammingdistance_              _pgahammingdistance_
#define pgasetintegerallele_             _pgasetintegerallele_
#define pgagetintegerallele_             _pgagetintegerallele_
#define pgasetintegerinitpermute_        _pgasetintegerinitpermute_
#define pgasetintegerinitrange_          _pgasetintegerinitrange_
#define pgagetintegerinittype_           _pgagetintegerinittype_
#define pgagetminintegerinitvalue_       _pgagetminintegerinitvalue_
#define pgagetmaxintegerinitvalue_       _pgagetmaxintegerinitvalue_
#define pgamutate_                       _pgamutate_
#define pgasetmutationtype_              _pgasetmutationtype_
#define pgagetmutationtype_              _pgagetmutationtype_
#define pgasetmutationrealvalue_         _pgasetmutationrealvalue_
#define pgagetmutationrealvalue_         _pgagetmutationrealvalue_
#define pgasetmutationintegervalue_      _pgasetmutationintegervalue_
#define pgagetmutationintegervalue_      _pgagetmutationintegervalue_
#define pgasetmutationboundedflag_       _pgasetmutationboundedflag_
#define pgagetmutationboundedflag_       _pgagetmutationboundedflag_
#define pgasetmutationprob_              _pgasetmutationprob_
#define pgagetmutationprob_              _pgagetmutationprob_
#define pgarungm_                        _pgarungm_
#define pgaevaluate_                     _pgaevaluate_
#define pgabuilddatatype_                _pgabuilddatatype_
#define pgasendindividual_               _pgasendindividual_
#define pgareceiveindividual_            _pgareceiveindividual_
#define pgasendreceiveindividual_        _pgasendreceiveindividual_
#define pgagetrank_                      _pgagetrank_
#define pgagetnumprocs_                  _pgagetnumprocs_
#define pgasetcommunicator_              _pgasetcommunicator_
#define pgagetcommunicator_              _pgagetcommunicator_
#define pgarun_                          _pgarun_
#define pgarunmutationandcrossover_      _pgarunmutationandcrossover_
#define pgarunmutationorcrossover_       _pgarunmutationorcrossover_
#define pgaupdategeneration_             _pgaupdategeneration_
#define pgagetdatatype_                  _pgagetdatatype_
#define pgagetoptdirflag_                _pgagetoptdirflag_
#define pgagetstringlength_              _pgagetstringlength_
#define pgagetgaitervalue_               _pgagetgaitervalue_
#define pgasetmutationorcrossoverflag_   _pgasetmutationorcrossoverflag_
#define pgasetmutationandcrossoverflag_  _pgasetmutationandcrossoverflag_
#define pgagetmutationorcrossoverflag_   _pgagetmutationorcrossoverflag_
#define pgagetmutationandcrossoverflag_  _pgagetmutationandcrossoverflag_
#define pgasortpop_                      _pgasortpop_
#define pgagetpopsize_                   _pgagetpopsize_
#define pgagetnumreplacevalue_           _pgagetnumreplacevalue_
#define pgagetpopreplacetype_            _pgagetpopreplacetype_
#define pgagetsortedpopindex_            _pgagetsortedpopindex_
#define pgasetpopsize_                   _pgasetpopsize_
#define pgasetnumreplacevalue_           _pgasetnumreplacevalue_
#define pgasetpopreplacetype_            _pgasetpopreplacetype_
#define pgarandomflip_                   _pgarandomflip_
#define pgarandominterval_               _pgarandominterval_
#define pgarandom01_                     _pgarandom01_
#define pgarandomuniform_                _pgarandomuniform_
#define pgarandomgaussian_               _pgarandomgaussian_
#define pgagetrandomseed_                _pgagetrandomseed_
#define pgasetrandomseed_                _pgasetrandomseed_
#define pgasetrealallele_                _pgasetrealallele_
#define pgagetrealallele_                _pgagetrealallele_
#define pgasetrealinitpercent_           _pgasetrealinitpercent_
#define pgasetrealinitrange_             _pgasetrealinitrange_
#define pgagetminrealinitvalue_          _pgagetminrealinitvalue_
#define pgagetmaxrealinitvalue_          _pgagetmaxrealinitvalue_
#define pgagetrealinittype_              _pgagetrealinittype_
#define pgaprintreport_                  _pgaprintreport_
#define pgasetprintoptions_              _pgasetprintoptions_
#define pgasetprintfrequencyvalue_       _pgasetprintfrequencyvalue_
#define pgagetprintfrequencyvalue_       _pgagetprintfrequencyvalue_
#define pgaprintpopulation_              _pgaprintpopulation_
#define pgaprintindividual_              _pgaprintindividual_
#define pgaprintstring_                  _pgaprintstring_
#define pgaprintcontextvariable_         _pgaprintcontextvariable_
#define pgarestart_                      _pgarestart_
#define pgasetrestartflag_               _pgasetrestartflag_
#define pgagetrestartflag_               _pgagetrestartflag_
#define pgasetrestartfrequencyvalue_     _pgasetrestartfrequencyvalue_
#define pgagetrestartfrequencyvalue_     _pgagetrestartfrequencyvalue_
#define pgasetrestartallelechangeprob_   _pgasetrestartallelechangeprob_
#define pgagetrestartallelechangeprob_   _pgagetrestartallelechangeprob_
#define pgaselect_                       _pgaselect_
#define pgaselectnextindex_              _pgaselectnextindex_
#define pgasetselecttype_                _pgasetselecttype_
#define pgagetselecttype_                _pgagetselecttype_
#define pgasetptournamentprob_           _pgasetptournamentprob_
#define pgagetptournamentprob_           _pgagetptournamentprob_
#define pgadone_                         _pgadone_
#define pgacheckstoppingconditions_      _pgacheckstoppingconditions_
#define pgasetstoppingruletype_          _pgasetstoppingruletype_
#define pgagetstoppingruletype_          _pgagetstoppingruletype_
#define pgasetmaxgaitervalue_            _pgasetmaxgaitervalue_
#define pgagetmaxgaitervalue_            _pgagetmaxgaitervalue_
#define pgasetmaxnochangevalue_          _pgasetmaxnochangevalue_
#define pgasetmaxsimilarityvalue_        _pgasetmaxsimilarityvalue_
#define pgaerror_                        _pgaerror_
#define pgadestroy_                      _pgadestroy_
#define pgagetmaxmachineintvalue_        _pgagetmaxmachineintvalue_
#define pgagetminmachineintvalue_        _pgagetminmachineintvalue_
#define pgagetmaxmachinedoublevalue_     _pgagetmaxmachinedoublevalue_
#define pgagetminmachinedoublevalue_     _pgagetminmachinedoublevalue_
#define pgausage_                        _pgausage_
#define pgaprintversionnumber_           _pgaprintversionnumber_
#define pgasetuserfunction_              _pgasetuserfunction_
#define pgamean_                         _pgamean_
#define pgastddev_                       _pgastddev_
#define pgaround_                        _pgaround_
#define pgacopyindividual_               _pgacopyindividual_
#define pgachecksum_                     _pgachecksum_
#define pgagetworstindex_                _pgagetworstindex_
#define pgagetbestindex_                 _pgagetbestindex_

#elif !defined(FORTRANUNDERSCORE)
#define pgasetbinaryallele_              pgasetbinaryallele
#define pgagetbinaryallele_              pgagetbinaryallele
#define pgasetbinaryinitprob_            pgasetbinaryinitprob
#define pgagetbinaryinitprob_            pgagetbinaryinitprob
#define pgasetcharacterallele_           pgasetcharacterallele
#define pgagetcharacterallele_           pgagetcharacterallele
#define pgasetcharacterinittype_         pgasetcharacterinittype
#define pgacreate_                       pgacreate
#define pgasetup_                        pgasetup
#define pgasetrandominitflag_            pgasetrandominitflag
#define pgagetrandominitflag_            pgagetrandominitflag
#define pgacrossover_                    pgacrossover
#define pgagetcrossovertype_             pgagetcrossovertype
#define pgagetcrossoverprob_             pgagetcrossoverprob
#define pgagetuniformcrossoverprob_      pgagetuniformcrossoverprob
#define pgasetcrossovertype_             pgasetcrossovertype
#define pgasetcrossoverprob_             pgasetcrossoverprob
#define pgasetuniformcrossoverprob_      pgasetuniformcrossoverprob
#define pgadebugprint_                   pgadebugprint
#define pgasetdebuglevel_                pgasetdebuglevel
#define pgacleardebuglevel_              pgacleardebuglevel
#define pgasetdebuglevelbyname_          pgasetdebuglevelbyname
#define pgacleardebuglevelbyname_        pgacleardebuglevelbyname
#define pgaduplicate_                    pgaduplicate
#define pgachange_                       pgachange
#define pgasetnoduplicatesflag_          pgasetnoduplicatesflag
#define pgagetnoduplicatesflag_          pgagetnoduplicatesflag
#define pgasetevaluation_                pgasetevaluation
#define pgagetevaluation_                pgagetevaluation
#define pgasetevaluationuptodateflag_    pgasetevaluationuptodateflag
#define pgagetevaluationuptodateflag_    pgagetevaluationuptodateflag
#define pgagetrealfrombinary_            pgagetrealfrombinary
#define pgagetrealfromgraycode_          pgagetrealfromgraycode
#define pgaencoderealasbinary_           pgaencoderealasbinary
#define pgaencoderealasgraycode_         pgaencoderealasgraycode
#define pgagetintegerfrombinary_         pgagetintegerfrombinary
#define pgagetintegerfromgraycode_       pgagetintegerfromgraycode
#define pgaencodeintegerasbinary_        pgaencodeintegerasbinary
#define pgaencodeintegerasgraycode_      pgaencodeintegerasgraycode
#define pgafitness_                      pgafitness
#define pgarank_                         pgarank
#define pgagetfitness_                   pgagetfitness
#define pgagetfitnesstype_               pgagetfitnesstype
#define pgagetfitnessmintype_            pgagetfitnessmintype
#define pgagetmaxfitnessrank_            pgagetmaxfitnessrank
#define pgasetfitnesstype_               pgasetfitnesstype
#define pgasetfitnessmintype_            pgasetfitnessmintype
#define pgasetmaxfitnessrank_            pgasetmaxfitnessrank
#define pgasetfitnesscmaxvalue_          pgasetfitnesscmaxvalue
#define pgagetfitnesscmaxvalue_          pgagetfitnesscmaxvalue
#define pgahammingdistance_              pgahammingdistance
#define pgasetintegerallele_             pgasetintegerallele
#define pgagetintegerallele_             pgagetintegerallele
#define pgasetintegerinitpermute_        pgasetintegerinitpermute
#define pgasetintegerinitrange_          pgasetintegerinitrange
#define pgagetintegerinittype_           pgagetintegerinittype
#define pgagetminintegerinitvalue_       pgagetminintegerinitvalue
#define pgagetmaxintegerinitvalue_       pgagetmaxintegerinitvalue
#define pgamutate_                       pgamutate
#define pgasetmutationtype_              pgasetmutationtype
#define pgagetmutationtype_              pgagetmutationtype
#define pgasetmutationrealvalue_         pgasetmutationrealvalue
#define pgagetmutationrealvalue_         pgagetmutationrealvalue
#define pgasetmutationintegervalue_      pgasetmutationintegervalue
#define pgagetmutationintegervalue_      pgagetmutationintegervalue
#define pgasetmutationboundedflag_       pgasetmutationboundedflag
#define pgagetmutationboundedflag_       pgagetmutationboundedflag
#define pgasetmutationprob_              pgasetmutationprob
#define pgagetmutationprob_              pgagetmutationprob
#define pgarungm_                        pgarungm
#define pgaevaluate_                     pgaevaluate
#define pgabuilddatatype_                pgabuilddatatype
#define pgasendindividual_               pgasendindividual
#define pgareceiveindividual_            pgareceiveindividual
#define pgasendreceiveindividual_        pgasendreceiveindividual
#define pgagetrank_                      pgagetrank
#define pgagetnumprocs_                  pgagetnumprocs
#define pgasetcommunicator_              pgasetcommunicator
#define pgagetcommunicator_              pgagetcommunicator
#define pgarun_                          pgarun
#define pgarunmutationandcrossover_      pgarunmutationandcrossover
#define pgarunmutationorcrossover_       pgarunmutationorcrossover
#define pgaupdategeneration_             pgaupdategeneration
#define pgagetdatatype_                  pgagetdatatype
#define pgagetoptdirflag_                pgagetoptdirflag
#define pgagetstringlength_              pgagetstringlength
#define pgagetgaitervalue_               pgagetgaitervalue
#define pgasetmutationorcrossoverflag_   pgasetmutationorcrossoverflag
#define pgasetmutationandcrossoverflag_  pgasetmutationandcrossoverflag
#define pgagetmutationorcrossoverflag_   pgagetmutationorcrossoverflag
#define pgagetmutationandcrossoverflag_  pgagetmutationandcrossoverflag
#define pgasortpop_                      pgasortpop
#define pgagetpopsize_                   pgagetpopsize
#define pgagetnumreplacevalue_           pgagetnumreplacevalue
#define pgagetpopreplacetype_            pgagetpopreplacetype
#define pgagetsortedpopindex_            pgagetsortedpopindex
#define pgasetpopsize_                   pgasetpopsize
#define pgasetnumreplacevalue_           pgasetnumreplacevalue
#define pgasetpopreplacetype_            pgasetpopreplacetype
#define pgarandomflip_                   pgarandomflip
#define pgarandominterval_               pgarandominterval
#define pgarandom01_                     pgarandom01
#define pgarandomuniform_                pgarandomuniform
#define pgarandomgaussian_               pgarandomgaussian
#define pgagetrandomseed_                pgagetrandomseed
#define pgasetrandomseed_                pgasetrandomseed
#define pgasetrealallele_                pgasetrealallele
#define pgagetrealallele_                pgagetrealallele
#define pgasetrealinitpercent_           pgasetrealinitpercent
#define pgasetrealinitrange_             pgasetrealinitrange
#define pgagetminrealinitvalue_          pgagetminrealinitvalue
#define pgagetmaxrealinitvalue_          pgagetmaxrealinitvalue
#define pgagetrealinittype_              pgagetrealinittype
#define pgaprintreport_                  pgaprintreport
#define pgasetprintoptions_              pgasetprintoptions
#define pgasetprintfrequencyvalue_       pgasetprintfrequencyvalue
#define pgagetprintfrequencyvalue_       pgagetprintfrequencyvalue
#define pgaprintpopulation_              pgaprintpopulation
#define pgaprintindividual_              pgaprintindividual
#define pgaprintstring_                  pgaprintstring
#define pgaprintcontextvariable_         pgaprintcontextvariable
#define pgarestart_                      pgarestart
#define pgasetrestartflag_               pgasetrestartflag
#define pgagetrestartflag_               pgagetrestartflag
#define pgasetrestartfrequencyvalue_     pgasetrestartfrequencyvalue
#define pgagetrestartfrequencyvalue_     pgagetrestartfrequencyvalue
#define pgasetrestartallelechangeprob_   pgasetrestartallelechangeprob
#define pgagetrestartallelechangeprob_   pgagetrestartallelechangeprob
#define pgaselect_                       pgaselect
#define pgaselectnextindex_              pgaselectnextindex
#define pgasetselecttype_                pgasetselecttype
#define pgagetselecttype_                pgagetselecttype
#define pgasetptournamentprob_           pgasetptournamentprob
#define pgagetptournamentprob_           pgagetptournamentprob
#define pgadone_                         pgadone
#define pgacheckstoppingconditions_      pgacheckstoppingconditions
#define pgasetstoppingruletype_          pgasetstoppingruletype
#define pgagetstoppingruletype_          pgagetstoppingruletype
#define pgasetmaxgaitervalue_            pgasetmaxgaitervalue
#define pgagetmaxgaitervalue_            pgagetmaxgaitervalue
#define pgasetmaxnochangevalue_          pgasetmaxnochangevalue
#define pgasetmaxsimilarityvalue_        pgasetmaxsimilarityvalue
#define pgaerror_                        pgaerror
#define pgadestroy_                      pgadestroy
#define pgagetmaxmachineintvalue_        pgagetmaxmachineintvalue
#define pgagetminmachineintvalue_        pgagetminmachineintvalue
#define pgagetmaxmachinedoublevalue_     pgagetmaxmachinedoublevalue
#define pgagetminmachinedoublevalue_     pgagetminmachinedoublevalue
#define pgausage_                        pgausage
#define pgaprintversionnumber_           pgaprintversionnumber
#define pgasetuserfunction_              pgasetuserfunction
#define pgamean_                         pgamean
#define pgastddev_                       pgastddev
#define pgaround_                        pgaround
#define pgacopyindividual_               pgacopyindividual
#define pgachecksum_                     pgachecksum
#define pgagetworstindex_                pgagetworstindex
#define pgagetbestindex_                 pgagetbestindex
#endif

void pgasetbinaryallele_(PGAContext **ftx, int *p, int *pop, int *i,
     int *val);
int pgagetbinaryallele_(PGAContext **ftx, int *p, int *pop, int *i);
void pgasetbinaryinitprob_(PGAContext **ftx, double *probability);
double pgagetbinaryinitprob_(PGAContext **ftx);
void pgasetcharacterallele_(PGAContext **ftx, int *p, int *pop, int *i,
     char *val);
void pgagetcharacterallele_(char *retval_ptr, int retval_len, PGAContext **ftx,
     int *p, int *pop, int *i);
void pgasetcharacterinittype_(PGAContext **ftx, int *value);
unsigned long pgacreate_(int *datatype, int *len, int *maxormin);
void pgasetup_(PGAContext **ftx);
void pgasetrandominitflag_(PGAContext **ftx, int *RandomBoolean);
int pgagetrandominitflag_(PGAContext **ftx);
void pgacrossover_(PGAContext **ftx, int *m1, int *m2, int *oldpop, int *t1,
     int *t2, int *newpop);
int pgagetcrossovertype_(PGAContext **ftx);
double pgagetcrossoverprob_(PGAContext **ftx);
double pgagetuniformcrossoverprob_(PGAContext **ftx);
void pgasetcrossovertype_(PGAContext **ftx, int *crossover_type);
void pgasetcrossoverprob_(PGAContext **ftx, double *crossover_prob);
void pgasetuniformcrossoverprob_(PGAContext **ftx,
     double *uniform_cross_prob);
void pgadebugprint_(PGAContext **ftx, int *level, char *funcname, char *msg,
     int *datatype, void *data, int len1, int len2);
void pgasetdebuglevel_(PGAContext **ftx, int *level);
void pgacleardebuglevel_(PGAContext **ftx, int *level);
void pgasetdebuglevelbyname_(PGAContext **ftx, char *name, int len);
void pgacleardebuglevelbyname_(PGAContext **ftx, char *name, int len);
int pgaduplicate_(PGAContext **ftx, int *j, int *pop1, int *pop2, int *n);
void pgachange_(PGAContext **ftx, int *j, int *popindex);
void pgasetnoduplicatesflag_(PGAContext **ftx, int *no_dup);
int pgagetnoduplicatesflag_(PGAContext **ftx);
void pgasetevaluation_( PGAContext **ftx, int *p, int *pop, double *val );
double pgagetevaluation_(PGAContext **ftx, int *p, int *pop);
void pgasetevaluationuptodateflag_(PGAContext **ftx, int *p, int *pop, int *status);
int pgagetevaluationuptodateflag_(PGAContext **ftx, int *p, int *pop);
double pgagetrealfrombinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper);
double pgagetrealfromgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper);
void pgaencoderealasbinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper,
     double *value);
void pgaencoderealasgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper,
     double *value);
int pgagetintegerfrombinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end);
int pgagetintegerfromgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end);
void pgaencodeintegerasbinary_(PGAContext **ftx, int *p, int *pop,
     int*start, int *end, int *value);
void pgaencodeintegerasgraycode_(PGAContext **ftx, int *p, int *pop,
     int*start, int *end, int *value);
void pgafitness_(PGAContext **ftx, int *popindex);
int pgarank_(PGAContext **ftx, int *p, int *order, int *n);
double pgagetfitness_(PGAContext **ftx, int *p, int *pop);
int pgagetfitnesstype_(PGAContext **ftx);
int pgagetfitnessmintype_(PGAContext **ftx);
double pgagetmaxfitnessrank_(PGAContext **ftx);
void pgasetfitnesstype_(PGAContext **ftx, int *fitness_type);
void pgasetfitnessmintype_(PGAContext **ftx, int *fitness_type);
void pgasetmaxfitnessrank_(PGAContext **ftx, double *fitness_rank_max);
void pgasetfitnesscmaxvalue_(PGAContext **ftx, double *val);
double pgagetfitnesscmaxvalue_(PGAContext **ftx);
double pgahammingdistance_(PGAContext **ftx, int *popindex);
void pgasetintegerallele_(PGAContext **ftx, int *p, int *pop, int *i,
     int *val);
int pgagetintegerallele_(PGAContext **ftx, int *p, int *pop, int *i);
void pgasetintegerinitpermute_(PGAContext **ftx, int *min, int *max);
void pgasetintegerinitrange_ (PGAContext **ftx, int *min, int *max);
int pgagetintegerinittype_(PGAContext **ftx);
int pgagetminintegerinitvalue_ (PGAContext **ftx, int *i);
int pgagetmaxintegerinitvalue_ (PGAContext **ftx, int *i);
void pgamutate_(PGAContext **ftx, int *p, int *pop);
void pgasetmutationtype_(PGAContext **ftx, int *mutation_type);
int pgagetmutationtype_(PGAContext **ftx);
void pgasetmutationrealvalue_(PGAContext **ftx, double *val);
double pgagetmutationrealvalue_(PGAContext **ftx);
void pgasetmutationintegervalue_(PGAContext **ftx, int *val);
int pgagetmutationintegervalue_(PGAContext **ftx);
void pgasetmutationboundedflag_(PGAContext **ftx, int *val);
int pgagetmutationboundedflag_(PGAContext **ftx);
void pgasetmutationprob_(PGAContext **ftx, double *mutation_prob);
double pgagetmutationprob_(PGAContext **ftx);
void pgarungm_(PGAContext **ftx, double (*f)(PGAContext *, int, int),
     MPI_Comm *comm);
void pgaevaluate_(PGAContext **ftx, int *pop,
     double (*f)(PGAContext *, int, int), MPI_Comm *comm);
unsigned long pgabuilddatatype_(PGAContext **ftx, int *p, int *pop);
void pgasendindividual_(PGAContext **ftx, int *p, int *pop, int *dest, int *tag, MPI_Comm *comm);
void pgareceiveindividual_(PGAContext **ftx, int *p, int *pop, int *source, int *tag, MPI_Comm *comm, MPI_Status *status);
void pgasendreceiveindividual_(PGAContext **ftx, int *send_p, int *send_pop, int *dest, int *send_tag, int *recv_p, int *recv_pop, int *source, int *recv_tag, MPI_Comm *comm, MPI_Status *status);
int pgagetrank_(PGAContext **ftx, MPI_Comm *comm);
int pgagetnumprocs_(PGAContext **ftx, MPI_Comm *comm);
void pgasetcommunicator_(PGAContext **ftx, MPI_Comm *comm);
MPI_Comm pgagetcommunicator_(PGAContext **ftx);
void pgarun_(PGAContext **ftx,
     double (*evaluate)(PGAContext *c, int p, int pop));
void pgarunmutationandcrossover_(PGAContext **ftx, int *oldpop,
     int *newpop);
void pgarunmutationorcrossover_(PGAContext **ftx, int *oldpop, int *newpop);
void pgaupdategeneration_(PGAContext **ftx, MPI_Comm *comm);
int pgagetdatatype_(PGAContext **ftx);
int pgagetoptdirflag_(PGAContext **ftx);
int pgagetstringlength_(PGAContext **ftx);
int pgagetgaitervalue_(PGAContext **ftx);
void pgasetmutationorcrossoverflag_(PGAContext **ftx, int *flag);
void pgasetmutationandcrossoverflag_(PGAContext **ftx, int *flag);
int pgagetmutationorcrossoverflag_(PGAContext **ftx);
int pgagetmutationandcrossoverflag_(PGAContext **ftx);
void pgasortpop_(PGAContext **ftx, int *pop);
int pgagetpopsize_(PGAContext **ftx);
int pgagetnumreplacevalue_(PGAContext **ftx);
int pgagetpopreplacetype_(PGAContext **ftx);
int pgagetsortedpopindex_(PGAContext **ftx, int *n);
void pgasetpopsize_(PGAContext **ftx, int *popsize);
void pgasetnumreplacevalue_(PGAContext **ftx, int *pop_replace);
void pgasetpopreplacetype_(PGAContext **ftx, int *pop_replace);
int pgarandomflip_(PGAContext **ftx, double *p);
int pgarandominterval_(PGAContext **ftx, int *start, int *end);
double pgarandom01_(PGAContext **ftx, int *newseed);
double pgarandomuniform_(PGAContext **ftx, double *start, double *end);
double pgarandomgaussian_(PGAContext **ftx, double *mean, double *sigma);
int pgagetrandomseed_(PGAContext **ftx);
void pgasetrandomseed_(PGAContext **ftx, int *seed);
void pgasetrealallele_(PGAContext **ftx, int *p, int *pop, int *i,
     double *val);
double pgagetrealallele_(PGAContext **ftx, int *p, int *pop, int *i);
void pgasetrealinitpercent_(PGAContext **ftx, double *median, double *percent);
void pgasetrealinitrange_ (PGAContext **ftx, double *min, double *max);
double pgagetminrealinitvalue_(PGAContext **ftx, int *i);
double pgagetmaxrealinitvalue_(PGAContext **ftx, int *i);
int pgagetrealinittype_(PGAContext **ftx);
void pgaprintreport_(PGAContext **ftx, char *name, int *pop, int len);
void pgasetprintoptions_(PGAContext **ftx, int *option);
void pgasetprintfrequencyvalue_(PGAContext **ftx, int *print_freq);
int pgagetprintfrequencyvalue_(PGAContext **ftx);
void pgaprintpopulation_(PGAContext **ftx, char *name, int *pop, int len);
void pgaprintindividual_ (PGAContext **ftx, char *name, int *p,
     int *pop, int len);
void pgaprintstring_ (PGAContext **ftx, char *name, int *p,
     int *pop, int len);
void pgaprintcontextvariable_(PGAContext **ftx, char *name, int len);
void pgarestart_(PGAContext **ftx, int *source_pop, int *dest_pop);
void pgasetrestartflag_(PGAContext **ftx, int *val);
int pgagetrestartflag_(PGAContext **ftx);
void pgasetrestartfrequencyvalue_(PGAContext **ftx, int *numiter);
int pgagetrestartfrequencyvalue_(PGAContext **ftx);
void pgasetrestartallelechangeprob_(PGAContext **ftx, double *prob);
double pgagetrestartallelechangeprob_(PGAContext **ftx);
void pgaselect_(PGAContext **ftx, int *popix);
int pgaselectnextindex_(PGAContext **ftx);
void pgasetselecttype_(PGAContext **ftx, int *select_type);
int pgagetselecttype_(PGAContext **ftx);
void pgasetptournamentprob_(PGAContext **ftx, double *ptournament_prob);
double pgagetptournamentprob_(PGAContext **ftx);
int pgadone_(PGAContext **ftx, MPI_Comm *comm);
int pgacheckstoppingconditions_(PGAContext **ftx);
void pgasetstoppingruletype_(PGAContext **ftx, int *stoprule);
int pgagetstoppingruletype_(PGAContext **ftx);
void pgasetmaxgaitervalue_(PGAContext **ftx, int *maxiter);
int pgagetmaxgaitervalue_(PGAContext **ftx);
void pgasetmaxnochangevalue_(PGAContext **ftx, int *max_no_change);
void pgasetmaxsimilarityvalue_(PGAContext **ftx, int *max_similarity);
void pgaerror_(PGAContext **ftx, char *msg, int *level, int *datatype,
     void **data, int len);
void pgadestroy_(PGAContext **ftx);
int pgagetmaxmachineintvalue_(PGAContext **ftx);
int pgagetminmachineintvalue_(PGAContext **ftx);
double pgagetmaxmachinedoublevalue_(PGAContext **ftx);
double pgagetminmachinedoublevalue_(PGAContext **ftx);
void pgausage_(PGAContext **ftx);
void pgaprintversionnumber_(PGAContext **ftx);
void pgasetuserfunction_(PGAContext **ftx, int *constant, void *f);
double pgamean_(PGAContext **ftx, double *a, int *n);
double pgastddev_(PGAContext **ftx, double *a, int *n, double *m);
int pgaround_(PGAContext **ftx, double *x);
void pgacopyindividual_(PGAContext **ftx, int *i, int *p1, int *j, int *p2);
int pgachecksum_(PGAContext **ftx, int *p, int *pop);
int pgagetworstindex_(PGAContext **ftx, int *pop);
int pgagetbestindex_(PGAContext **ftx, int *pop);

void pgasetbinaryallele_(PGAContext **ftx, int *p, int *pop, int *i,
     int *val)
{
     PGASetBinaryAllele(*ftx,
	   *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
	   *pop, *i-1, *val);
}

int pgagetbinaryallele_(PGAContext **ftx, int *p, int *pop, int *i)
{
     return PGAGetBinaryAllele(*ftx,
		  *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		  *pop, *i-1);
}

void pgasetbinaryinitprob_(PGAContext **ftx, double *probability)
{
     PGASetBinaryInitProb  (*ftx, *probability);
}

double pgagetbinaryinitprob_(PGAContext **ftx)
{
     return PGAGetBinaryInitProb  (*ftx);
}

void pgasetcharacterallele_(PGAContext **ftx, int *p, int *pop, int *i,
     char *val)
{
     PGASetCharacterAllele(*ftx,
	   *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
	   *pop, *i-1, *val);
}

void pgagetcharacterallele_(char *retval_ptr, int retval_len, PGAContext **ftx,
     int *p, int *pop, int *i)
{
     *retval_ptr = PGAGetCharacterAllele(*ftx,
		  *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		  *pop, *i-1);
}

void pgasetcharacterinittype_(PGAContext **ftx, int *value)
{
     PGASetCharacterInitType  (*ftx, *value);
}

unsigned long pgacreate_(int *datatype, int *len, int *maxormin)
{
     int argc;
     char *argv[1];
     PGAContext *ctx;

     argv[0] = "pgapack";
     argc = 1;

     ctx = PGACreate(&argc, argv, *datatype, *len, *maxormin);
     ctx->sys.UserFortran = PGA_TRUE;

     return (unsigned long)ctx;
}

void pgasetup_(PGAContext **ftx)
{
     PGASetUp  (*ftx);
}

void pgasetrandominitflag_(PGAContext **ftx, int *RandomBoolean)
{
     PGASetRandomInitFlag  (*ftx, *RandomBoolean);
}

int pgagetrandominitflag_(PGAContext **ftx)
{
     return PGAGetRandomInitFlag  (*ftx);
}

void pgacrossover_(PGAContext **ftx, int *m1, int *m2, int *oldpop, int *t1,
     int *t2, int *newpop)
{
     PGACrossover (*ftx,
		   *m1 == PGA_TEMP1 || *m1 == PGA_TEMP2 ? *m1 : *m1-1,
		   *m2 == PGA_TEMP1 || *m2 == PGA_TEMP2 ? *m2 : *m2-1,
		   *oldpop,
		   *t1 == PGA_TEMP1 || *t1 == PGA_TEMP2 ? *t1 : *t1-1,
		   *t2 == PGA_TEMP1 || *t2 == PGA_TEMP2 ? *t2 : *t2-1,
		   *newpop);
}

int pgagetcrossovertype_(PGAContext **ftx)
{
     return PGAGetCrossoverType  (*ftx);
}

double pgagetcrossoverprob_(PGAContext **ftx)
{
     return PGAGetCrossoverProb  (*ftx);
}

double pgagetuniformcrossoverprob_(PGAContext **ftx)
{
     return PGAGetUniformCrossoverProb  (*ftx);
}

void pgasetcrossovertype_(PGAContext **ftx, int *crossover_type)
{
     PGASetCrossoverType  (*ftx, *crossover_type);
}

void pgasetcrossoverprob_(PGAContext **ftx, double *crossover_prob)
{
     PGASetCrossoverProb  (*ftx, *crossover_prob);
}

void pgasetuniformcrossoverprob_(PGAContext **ftx,
     double *uniform_cross_prob)
{
     PGASetUniformCrossoverProb  (*ftx, *uniform_cross_prob);
}

#if OPTIMIZE==0
void pgadebugprint_(PGAContext **ftx, int *level, char *funcname, char *msg,
     int *datatype, void *data, int len1, int len2)
/* FORTRAN implicitly passes the lengths of funcname and msg into len1
   and len2, respectively */
{
     if (funcname[len1] != 0 || msg[len2] != 0)
	  funcname[len1] = msg[len2] = 0;
     PGADebugPrint(*ftx, *level, funcname, msg, *datatype, data );
}
#else
void pgadebugprint_(PGAContext **ftx, int *level, char *funcname, char *msg,
		    int *datatype, void *data, int len1, int len2)
{
     printf("PGADebugPrint is not supported in the optimized version of PGAPack.\n");
}
#endif

#if OPTIMIZE==0
void pgasetdebuglevel_(PGAContext **ftx, int *level)
{
    PGASetDebugLevel(*ftx, *level);
}
#else
void pgasetdebuglevel_(PGAContext **ftx, int *level)
{
    printf("PGASetDebugLevel is not supported in the optimized version of PGAPack.\n");
}
#endif
#if OPTIMIZE==0
void pgacleardebuglevel_(PGAContext **ftx, int *level)
{
    PGAClearDebugLevel(*ftx, *level);
}
#else
void pgacleardebuglevel_(PGAContext **ftx, int *level)
{
    printf("PGAClearDebugLevel is not supported in the optimized version of PGAPack.\n");
}
#endif
#if OPTIMIZE==0
void pgasetdebuglevelbyname_(PGAContext **ftx, char *name, int len)
{
    if (name[len] != 0)  name[len] = 0;
    PGASetDebugLevelByName(*ftx, name);
}
#else
void pgasetdebuglevelbyname_(PGAContext **ftx, char *name, int len)
{
    printf("PGASetDebugLevelByName is not supported in the optimized version of PGAPack.\n");
}
#endif
#if OPTIMIZE==0
void pgacleardebuglevelbyname_(PGAContext **ftx, char *name, int len)
{
    if (name[len] != 0)  name[len] = 0;
    PGAClearDebugLevelByName(*ftx, name);
}
#else
void pgacleardebuglevelbyname_(PGAContext **ftx, char *name, int len)
{
    printf("PGAClearDebugLevelByName is not supported in the optimized version of PGAPack.\n");
}
#endif
int pgaduplicate_(PGAContext **ftx, int *j, int *pop1, int *pop2, int *n)
{
     return PGADuplicate(*ftx,
		  *j == PGA_TEMP1 || *j == PGA_TEMP2 ? *j : *j-1,
		  *pop1, *pop2, *n);
}

void pgachange_(PGAContext **ftx, int *j, int *popindex)
{
     PGAChange(*ftx,
	   *j == PGA_TEMP1 || *j == PGA_TEMP2 ? *j : *j-1,
	   *popindex);
}

void pgasetnoduplicatesflag_(PGAContext **ftx, int *no_dup)
{
     PGASetNoDuplicatesFlag  (*ftx, *no_dup);
}

int pgagetnoduplicatesflag_(PGAContext **ftx)
{
     return PGAGetNoDuplicatesFlag  (*ftx);
}

void pgasetevaluation_( PGAContext **ftx, int *p, int *pop, double *val )
{
     PGASetEvaluation(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1,
           *pop, *val );
}

double pgagetevaluation_(PGAContext **ftx, int *p, int *pop)
{
     return PGAGetEvaluation(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1, *pop);
}

void pgasetevaluationuptodateflag_(PGAContext **ftx, int *p, int *pop, int *status)
{
     PGASetEvaluationUpToDateFlag(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1,
           *pop, *status);
}

int pgagetevaluationuptodateflag_(PGAContext **ftx, int *p, int *pop)
{
     return PGAGetEvaluationUpToDateFlag(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1, *pop);
}

double pgagetrealfrombinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper)
{
     return PGAGetRealFromBinary(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *lower, *upper);
}

double pgagetrealfromgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper)
{
     return PGAGetRealFromGrayCode(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *lower, *upper);
}

void pgaencoderealasbinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper,
     double *value)
{
     PGAEncodeRealAsBinary(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *lower, *upper, *value);
}

void pgaencoderealasgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end, double *lower, double *upper,
     double *value)
{
     PGAEncodeRealAsGrayCode(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *lower, *upper, *value);
}

int pgagetintegerfrombinary_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end)
{
     return PGAGetIntegerFromBinary(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1);
}

int pgagetintegerfromgraycode_(PGAContext **ftx, int *p, int *pop,
     int *start, int *end)
{
     return PGAGetIntegerFromGrayCode(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1);
}

void pgaencodeintegerasbinary_(PGAContext **ftx, int *p, int *pop,
     int*start, int *end, int *value)
{
     PGAEncodeIntegerAsBinary(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *value);
}

void pgaencodeintegerasgraycode_(PGAContext **ftx, int *p, int *pop,
     int*start, int *end, int *value)
{
     PGAEncodeIntegerAsGrayCode(*ftx,
          *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p :
          *p - 1,
          *pop, *start-1, *end-1, *value);
}

void pgafitness_(PGAContext **ftx, int *popindex)
{
     PGAFitness  (*ftx, *popindex);
}

int pgarank_(PGAContext **ftx, int *p, int *order, int *n)
{
    return PGARank(*ftx, *p-1, order, *n);
}

double pgagetfitness_(PGAContext **ftx, int *p, int *pop)
{
     return PGAGetFitness(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1, *pop);
}

int pgagetfitnesstype_(PGAContext **ftx)
{
     return PGAGetFitnessType  (*ftx);
}

int pgagetfitnessmintype_(PGAContext **ftx)
{
     return PGAGetFitnessMinType  (*ftx);
}

double pgagetmaxfitnessrank_(PGAContext **ftx)
{
     return PGAGetMaxFitnessRank  (*ftx);
}

void pgasetfitnesstype_(PGAContext **ftx, int *fitness_type)
{
     PGASetFitnessType  (*ftx, *fitness_type);
}

void pgasetfitnessmintype_(PGAContext **ftx, int *fitness_type)
{
     PGASetFitnessMinType  (*ftx, *fitness_type);
}

void pgasetmaxfitnessrank_(PGAContext **ftx, double *fitness_rank_max)
{
     PGASetMaxFitnessRank  (*ftx, *fitness_rank_max);
}

void pgasetfitnesscmaxvalue_(PGAContext **ftx, double *val)
{
     PGASetFitnessCmaxValue  (*ftx, *val);
}

double pgagetfitnesscmaxvalue_(PGAContext **ftx)
{
     return PGAGetFitnessCmaxValue  (*ftx);
}

double pgahammingdistance_(PGAContext **ftx, int *popindex)
{
     return PGAHammingDistance  (*ftx, *popindex);
}

void pgasetintegerallele_(PGAContext **ftx, int *p, int *pop, int *i,
     int *val)
{
     PGASetIntegerAllele(*ftx,
	   *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
	   *pop, *i-1, *val);
}

int pgagetintegerallele_(PGAContext **ftx, int *p, int *pop, int *i)
{
     return PGAGetIntegerAllele(*ftx,
		  *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		  *pop, *i-1);
}

void pgasetintegerinitpermute_(PGAContext **ftx, int *min, int *max)
{
     PGASetIntegerInitPermute  (*ftx, *min, *max);
}

void pgasetintegerinitrange_ (PGAContext **ftx, int *min, int *max)
{
     PGASetIntegerInitRange(*ftx, min, max);
}

int pgagetintegerinittype_(PGAContext **ftx)
{
     return PGAGetIntegerInitType  (*ftx);
}

int pgagetminintegerinitvalue_ (PGAContext **ftx, int *i)
{
     return PGAGetMinIntegerInitValue(*ftx, *i-1);
}

int pgagetmaxintegerinitvalue_ (PGAContext **ftx, int *i)
{
     return PGAGetMaxIntegerInitValue(*ftx, *i-1);
}

void pgamutate_(PGAContext **ftx, int *p, int *pop)
{
     PGAMutate(*ftx,
	   *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1, *pop);
}

void pgasetmutationtype_(PGAContext **ftx, int *mutation_type)
{
     PGASetMutationType  (*ftx, *mutation_type);
}

int pgagetmutationtype_(PGAContext **ftx)
{
     return PGAGetMutationType  (*ftx);
}

void pgasetmutationrealvalue_(PGAContext **ftx, double *val)
{
     PGASetMutationRealValue  (*ftx, *val);
}

double pgagetmutationrealvalue_(PGAContext **ftx)
{
     return PGAGetMutationRealValue  (*ftx);
}

void pgasetmutationintegervalue_(PGAContext **ftx, int *val)
{
     PGASetMutationIntegerValue  (*ftx, *val);
}

int pgagetmutationintegervalue_(PGAContext **ftx)
{
     return PGAGetMutationIntegerValue  (*ftx);
}

void pgasetmutationboundedflag_(PGAContext **ftx, int *val)
{
     PGASetMutationBoundedFlag  (*ftx, *val);
}

int pgagetmutationboundedflag_(PGAContext **ftx)
{
     return PGAGetMutationBoundedFlag  (*ftx);
}

void pgasetmutationprob_(PGAContext **ftx, double *mutation_prob)
{
     PGASetMutationProb  (*ftx, *mutation_prob);
}

double pgagetmutationprob_(PGAContext **ftx)
{
     return PGAGetMutationProb  (*ftx);
}

void pgarungm_(PGAContext **ftx, double (*f)(PGAContext *, int, int),
     MPI_Comm *comm)
{
     PGARunGM  (*ftx, (*f), *comm);
}

void pgaevaluate_(PGAContext **ftx, int *pop,
     double (*f)(PGAContext *, int, int), MPI_Comm *comm)
{
     PGAEvaluate  (*ftx, *pop, (*f), *comm);
}

unsigned long pgabuilddatatype_(PGAContext **ftx, int *p, int *pop)
{
     return((unsigned long)PGABuildDatatype(*ftx, 
                             *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
                             *pop));
}

void pgasendindividual_(PGAContext **ftx, int *p, int *pop, int *dest, int *tag, MPI_Comm *comm)
{
     PGASendIndividual(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
                       *pop, *dest, *tag, *comm);
}

void pgareceiveindividual_(PGAContext **ftx, int *p, int *pop, int *source, int *tag, MPI_Comm *comm, MPI_Status *status)
{
     PGAReceiveIndividual(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1,
                          *pop, *source, *tag, *comm, status);
}

void pgasendreceiveindividual_(PGAContext **ftx, int *send_p, int *send_pop, int *dest, int *send_tag, int *recv_p, int *recv_pop, int *source, int *recv_tag, MPI_Comm *comm, MPI_Status *status)
{
     PGASendReceiveIndividual(*ftx, 
          *send_p == PGA_TEMP1 || *send_p == PGA_TEMP2 ? *send_p : *send_p - 1,
          *send_pop, *dest, *send_tag, 
          *recv_p == PGA_TEMP1 || *recv_p == PGA_TEMP2 ? *recv_p : *recv_p - 1,
          *recv_pop, *source, *recv_tag, *comm, status);
}

int pgagetrank_(PGAContext **ftx, MPI_Comm *comm)
{
     return PGAGetRank  (*ftx, *comm);
}

int pgagetnumprocs_(PGAContext **ftx, MPI_Comm *comm)
{
     return PGAGetNumProcs  (*ftx, *comm);
}

void pgasetcommunicator_(PGAContext **ftx, MPI_Comm *comm)
{
     PGASetCommunicator  (*ftx, *comm);
}

MPI_Comm pgagetcommunicator_(PGAContext **ftx)
{
     return PGAGetCommunicator  (*ftx);
}

void pgarun_(PGAContext **ftx,
     double (*evaluate)(PGAContext *c, int p, int pop))
{
     PGARun  (*ftx, (*evaluate));
}

void pgarunmutationandcrossover_(PGAContext **ftx, int *oldpop,
     int *newpop)
{
     PGARunMutationAndCrossover  (*ftx, *oldpop, *newpop);
}

void pgarunmutationorcrossover_(PGAContext **ftx, int *oldpop, int *newpop)
{
     PGARunMutationOrCrossover  (*ftx, *oldpop, *newpop);
}

void pgaupdategeneration_(PGAContext **ftx, MPI_Comm *comm)
{
     PGAUpdateGeneration  (*ftx, *comm);
}

int pgagetdatatype_(PGAContext **ftx)
{
     return PGAGetDataType  (*ftx);
}

int pgagetoptdirflag_(PGAContext **ftx)
{
     return PGAGetOptDirFlag  (*ftx);
}

int pgagetstringlength_(PGAContext **ftx)
{
     return PGAGetStringLength  (*ftx);
}

int pgagetgaitervalue_(PGAContext **ftx)
{
     return PGAGetGAIterValue  (*ftx);
}

void pgasetmutationorcrossoverflag_(PGAContext **ftx, int *flag)
{
     PGASetMutationOrCrossoverFlag  (*ftx, *flag);
}

void pgasetmutationandcrossoverflag_(PGAContext **ftx, int *flag)
{
     PGASetMutationAndCrossoverFlag  (*ftx, *flag);
}

int pgagetmutationorcrossoverflag_(PGAContext **ftx)
{
     return PGAGetMutationOrCrossoverFlag  (*ftx);
}

int pgagetmutationandcrossoverflag_(PGAContext **ftx)
{
     return PGAGetMutationAndCrossoverFlag  (*ftx);
}

void pgasortpop_(PGAContext **ftx, int *pop)
{
     PGASortPop  (*ftx, *pop);
}

int pgagetpopsize_(PGAContext **ftx)
{
     return PGAGetPopSize  (*ftx);
}

int pgagetnumreplacevalue_(PGAContext **ftx)
{
     return PGAGetNumReplaceValue  (*ftx);
}

int pgagetpopreplacetype_(PGAContext **ftx)
{
     return PGAGetPopReplaceType  (*ftx);
}

int pgagetsortedpopindex_(PGAContext **ftx, int *n)
{
     return PGAGetSortedPopIndex(*ftx, *n-1);
}

void pgasetpopsize_(PGAContext **ftx, int *popsize)
{
     PGASetPopSize  (*ftx, *popsize);
}

void pgasetnumreplacevalue_(PGAContext **ftx, int *pop_replace)
{
     PGASetNumReplaceValue  (*ftx, *pop_replace);
}

void pgasetpopreplacetype_(PGAContext **ftx, int *pop_replace)
{
     PGASetPopReplaceType  (*ftx, *pop_replace);
}

int pgarandomflip_(PGAContext **ftx, double *p)
{
     return PGARandomFlip  (*ftx, *p);
}

int pgarandominterval_(PGAContext **ftx, int *start, int *end)
{
     return PGARandomInterval  (*ftx, *start, *end);
}

double pgarandom01_(PGAContext **ftx, int *newseed)
{
     return PGARandom01  (*ftx, *newseed);
}

double pgarandomuniform_(PGAContext **ftx, double *start, double *end)
{
     return PGARandomUniform  (*ftx, *start, *end);
}

double pgarandomgaussian_(PGAContext **ftx, double *mean, double *sigma)
{
     return PGARandomGaussian  (*ftx, *mean, *sigma);
}

int pgagetrandomseed_(PGAContext **ftx)
{
     return PGAGetRandomSeed  (*ftx);
}

void pgasetrandomseed_(PGAContext **ftx, int *seed)
{
     PGASetRandomSeed  (*ftx, *seed);
}

void pgasetrealallele_(PGAContext **ftx, int *p, int *pop, int *i,
     double *val)
{
     PGASetRealAllele(*ftx,
	   *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
	   *pop, *i-1, *val);
}

double pgagetrealallele_(PGAContext **ftx, int *p, int *pop, int *i)
{
     return PGAGetRealAllele(*ftx,
		  *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		  *pop, *i-1);
}

void pgasetrealinitpercent_(PGAContext **ftx, double *median, double *percent)
{
     PGASetRealInitPercent(*ftx, median, percent);
}

void pgasetrealinitrange_ (PGAContext **ftx, double *min, double *max)
{
     PGASetRealInitRange(*ftx, min, max);
}

double pgagetminrealinitvalue_(PGAContext **ftx, int *i)
{
     return PGAGetMinRealInitValue(*ftx, *i-1);
}

double pgagetmaxrealinitvalue_(PGAContext **ftx, int *i)
{
     return PGAGetMaxRealInitValue(*ftx, *i-1);
}

int pgagetrealinittype_(PGAContext **ftx)
{
     return PGAGetRealInitType  (*ftx);
}

void pgaprintreport_(PGAContext **ftx, char *name, int *pop, int len)
/* FORTRAN implicitly passes the length of name into len. */
{
     FILE *fp;
     if (name[len] != 0)
	  name[len] = 0;
     if (!strcmp(name, "STDOUT") || !strcmp(name, "stdout"))
     {
	  fp = stdout;
	  PGAPrintReport(*ftx, fp, *pop);
     }
     else if (!strcmp(name, "STDERR") || !strcmp(name, "stderr"))
     {
	  fp = stderr;
	  PGAPrintReport(*ftx, fp, *pop);
     }
     else
     {
	  fp = fopen(name, "a");
	  if (!fp)
	       PGAError(*ftx, "PGAPrintReport: Could not open file:",
			     PGA_FATAL, PGA_CHAR, (void *) name);
	  else
	  {
	       PGAPrintReport(*ftx, fp, *pop);
	       fclose(fp);
	  }
     }
}

void pgasetprintoptions_(PGAContext **ftx, int *option)
{
     PGASetPrintOptions  (*ftx, *option);
}

void pgasetprintfrequencyvalue_(PGAContext **ftx, int *print_freq)
{
     PGASetPrintFrequencyValue  (*ftx, *print_freq);
}

int pgagetprintfrequencyvalue_(PGAContext **ftx)
{
     return PGAGetPrintFrequencyValue  (*ftx);
}

void pgaprintpopulation_(PGAContext **ftx, char *name, int *pop, int len)
/* FORTRAN implicitly passes the length of name into len. */
{
     FILE *fp;
     if (name[len] != 0)
	  name[len] = 0;
     if (!strcmp(name, "STDOUT") || !strcmp(name, "stdout"))
     {
	  fp = stdout;
	  PGAPrintPopulation(*ftx, fp, *pop);
     }
     else if (!strcmp(name, "STDERR") || !strcmp(name, "stderr"))
     {
	  fp = stderr;
	  PGAPrintPopulation(*ftx, fp, *pop);
     }
     else
     {
	  fp = fopen(name, "a");
	  if (!fp)
	       PGAError(*ftx, "PGAPrintPopulation: Could not open file:",
			     PGA_FATAL, PGA_CHAR, (void *) name);
	  else
	  {
	       PGAPrintPopulation(*ftx, fp, *pop);
	       fclose(fp);
	  }
     }
}

void pgaprintindividual_ (PGAContext **ftx, char *name, int *p,
     int *pop, int len)
          /* FORTRAN implicitly passes the length of name into len. */
{
     FILE *fp;
     if (name[len] != 0)
	  name[len] = 0;
     if (!strcmp(name, "STDOUT") || !strcmp(name, "stdout"))
     {
	  fp = stdout;
	  PGAPrintIndividual(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		*pop);
     }
     else if (!strcmp(name, "STDERR") || !strcmp(name, "stderr"))
     {
	  fp = stderr;
	  PGAPrintIndividual(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		*pop);
     }
     else
     {
	  fp = fopen(name, "a");
	  if (!fp)
	       PGAError(*ftx, "PGAPrintIndividual: Could not open file:",
			     PGA_FATAL, PGA_CHAR, (void *) name);
	  else
	  {
	       PGAPrintIndividual(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		     *pop);
	       fclose(fp);
	  }
     }
}

void pgaprintstring_ (PGAContext **ftx, char *name, int *p,
     int *pop, int len)
          /* FORTRAN implicitly passes the length of name into len. */
{
     FILE *fp;
     if (name[len] != 0)
	  name[len] = 0;
     if (!strcmp(name, "STDOUT") || !strcmp(name, "stdout"))
     {
	  fp = stdout;
	  PGAPrintString(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		*pop);
     }
     else if (!strcmp(name, "STDERR") || !strcmp(name, "stderr"))
     {
	  fp = stderr;
	  PGAPrintString(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		*pop);
     }
     else
     {
	  fp = fopen(name, "a");
	  if (!fp)
	       PGAError(*ftx, "PGAPrintString: Could not open file:",
			     PGA_FATAL, PGA_CHAR, (void *) name);
	  else
	  {
	       PGAPrintString(*ftx, fp, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p - 1,
		     *pop);
	       fclose(fp);
	  }
     }
}

void pgaprintcontextvariable_(PGAContext **ftx, char *name, int len)
/* FORTRAN implicitly passes the length of name into len. */
{
     FILE *fp;
     if (name[len] != 0)
	  name[len] = 0;
     if (!strcmp(name, "STDOUT") || !strcmp(name, "stdout"))
     {
	  fp = stdout;
	  PGAPrintContextVariable(*ftx, fp);
     }
     else if (!strcmp(name, "STDERR") || !strcmp(name, "stderr"))
     {
	  fp = stderr;
	  PGAPrintContextVariable(*ftx, fp);
     }
     else
     {
	  fp = fopen(name, "a");
	  if (!fp)
	       PGAError(*ftx, "PGAPrintContextVariable: Could not open file:",
			     PGA_FATAL, PGA_CHAR, (void *) name);
	  else
	  {
	       PGAPrintContextVariable(*ftx, fp);
	       fclose(fp);
	  }
     }
}

void pgarestart_(PGAContext **ftx, int *source_pop, int *dest_pop)
{
     PGARestart  (*ftx, *source_pop, *dest_pop);
}

void pgasetrestartflag_(PGAContext **ftx, int *val)
{
     PGASetRestartFlag  (*ftx, *val);
}

int pgagetrestartflag_(PGAContext **ftx)
{
     return PGAGetRestartFlag  (*ftx);
}

void pgasetrestartfrequencyvalue_(PGAContext **ftx, int *numiter)
{
     PGASetRestartFrequencyValue  (*ftx, *numiter);
}

int pgagetrestartfrequencyvalue_(PGAContext **ftx)
{
     return PGAGetRestartFrequencyValue  (*ftx);
}

void pgasetrestartallelechangeprob_(PGAContext **ftx, double *prob)
{
     PGASetRestartAlleleChangeProb  (*ftx, *prob);
}

double pgagetrestartallelechangeprob_(PGAContext **ftx)
{
     return PGAGetRestartAlleleChangeProb  (*ftx);
}

void pgaselect_(PGAContext **ftx, int *popix)
{
     PGASelect  (*ftx, *popix);
}

int pgaselectnextindex_(PGAContext **ftx)
{
     return PGASelectNextIndex  (*ftx);
}

void pgasetselecttype_(PGAContext **ftx, int *select_type)
{
     PGASetSelectType  (*ftx, *select_type);
}

int pgagetselecttype_(PGAContext **ftx)
{
     return PGAGetSelectType  (*ftx);
}

void pgasetptournamentprob_(PGAContext **ftx, double *ptournament_prob)
{
     PGASetPTournamentProb  (*ftx, *ptournament_prob);
}

double pgagetptournamentprob_(PGAContext **ftx)
{
     return PGAGetPTournamentProb  (*ftx);
}

int pgadone_(PGAContext **ftx, MPI_Comm *comm)
{
     return PGADone  (*ftx, *comm);
}

int pgacheckstoppingconditions_(PGAContext **ftx)
{
     return PGACheckStoppingConditions  (*ftx);
}

void pgasetstoppingruletype_(PGAContext **ftx, int *stoprule)
{
     PGASetStoppingRuleType  (*ftx, *stoprule);
}

int pgagetstoppingruletype_(PGAContext **ftx)
{
     return PGAGetStoppingRuleType  (*ftx);
}

void pgasetmaxgaitervalue_(PGAContext **ftx, int *maxiter)
{
     PGASetMaxGAIterValue  (*ftx, *maxiter);
}

int pgagetmaxgaitervalue_(PGAContext **ftx)
{
     return PGAGetMaxGAIterValue  (*ftx);
}

void pgasetmaxnochangevalue_(PGAContext **ftx, int *max_no_change)
{
     PGASetMaxNoChangeValue  (*ftx, *max_no_change);
}

void pgasetmaxsimilarityvalue_(PGAContext **ftx, int *max_similarity)
{
     PGASetMaxSimilarityValue  (*ftx, *max_similarity);
}

void pgaerror_(PGAContext **ftx, char *msg, int *level, int *datatype,
     void **data, int len)
/* FORTRAN implicitly passes the length of msg into len. */
{
     if (msg[len] != 0)
	  msg[len] = 0;
     PGAError (*ftx, msg, *level, *datatype, *data);
}

void pgadestroy_(PGAContext **ftx)
{
     PGADestroy  (*ftx);
}

int pgagetmaxmachineintvalue_(PGAContext **ftx)
{
     return PGAGetMaxMachineIntValue  (*ftx);
}

int pgagetminmachineintvalue_(PGAContext **ftx)
{
     return PGAGetMinMachineIntValue  (*ftx);
}

double pgagetmaxmachinedoublevalue_(PGAContext **ftx)
{
     return PGAGetMaxMachineDoubleValue  (*ftx);
}

double pgagetminmachinedoublevalue_(PGAContext **ftx)
{
     return PGAGetMinMachineDoubleValue  (*ftx);
}

void pgausage_(PGAContext **ftx)
{
     PGAUsage  (*ftx);
}

void pgaprintversionnumber_(PGAContext **ftx)
{
     PGAPrintVersionNumber  (*ftx);
}

void pgasetuserfunction_(PGAContext **ftx, int *constant, void *f)
{
     PGASetUserFunction(*ftx, *constant, f);
}

double pgamean_(PGAContext **ftx, double *a, int *n)
{
     return PGAMean(*ftx, a, *n);
}

double pgastddev_(PGAContext **ftx, double *a, int *n, double *m)
{
     return PGAStddev(*ftx, a, *n, *m);
}

int pgaround_(PGAContext **ftx, double *x)
{
     return PGARound  (*ftx, *x);
}

void pgacopyindividual_(PGAContext **ftx, int *i, int *p1, int *j, int *p2)
{
     PGACopyIndividual(*ftx,
	   *i == PGA_TEMP1 || *i == PGA_TEMP2 ? *i : *i-1,
	   *p1,
	   *j == PGA_TEMP1 || *j == PGA_TEMP2 ? *j : *j-1,
	   *p2);
}

int pgachecksum_(PGAContext **ftx, int *p, int *pop)
{
     return PGACheckSum(*ftx, *p == PGA_TEMP1 || *p == PGA_TEMP2 ? *p : *p-1, *pop);
}

int pgagetworstindex_(PGAContext **ftx, int *pop)
{
     return PGAGetWorstIndex(*ftx, *pop) + 1;
}

int pgagetbestindex_(PGAContext **ftx, int *pop)
{
     return PGAGetBestIndex(*ftx, *pop) + 1;
}

