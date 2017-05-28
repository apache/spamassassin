      subroutine objfcn(n,x,f,nprob)
      integer n,nprob
      double precision f
      double precision x(n)
c     **********
c
c     subroutine objfcn
c
c     This subroutine defines the objective functions of eighteen
c     nonlinear unconstrained minimization problems. The values
c     of n for functions 1,2,3,4,5,10,11,12,16 and 17 are
c     3,6,3,2,3,2,4,3,2 and 4, respectively.
c     For function 7, n may be 2 or greater but is usually 6 or 9.
c     For functions 6,8,9,13,14,15 and 18 n may be variable,
c     however it must be even for function 14, a multiple of 4 for
c     function 15, and not greater than 50 for function 18.
c
c     The subroutine statement is
c
c       subroutine objfcn(n,x,f,nprob)
c
c     where
c
c       n is a positive integer input variable.
c
c       x is an input array of length n.
c
c       f is an output variable which contains the value of
c         the nprob objective function evaluated at x.
c
c       nprob is a positive integer input variable which defines the
c         number of the problem. nprob must not exceed 18.
c
c     Subprograms called
c
c       FORTRAN-supplied ... abs,atan,cos,dble,exp,log,sign,sin,sqrt
c
c     Argonne National Laboratory. MINPACK Project. march 1980.
c     Burton S. Garbow, Kenneth E. Hillstrom, Jorge J. More
c
c     **********
      integer i,iev,j
      double precision ap,arg,c2pdm6,cp0001,cp1,cp2,cp25,cp5,c1p5,
     *                 c2p25,c2p625,c3p5,c25,c29,c90,c100,c10000,
     *                 c1pd6,d1,d2,eight,fifty,five,four,one,r,s1,s2,
     *                 s3,t,t1,t2,t3,ten,th,three,tpi,two,zero
      double precision fvec(50),y(15)
      data zero,one,two,three,four,five,eight,ten,fifty
     *     /0.0d0,1.0d0,2.0d0,3.0d0,4.0d0,5.0d0,8.0d0,1.0d1,5.0d1/
      data c2pdm6,cp0001,cp1,cp2,cp25,cp5,c1p5,c2p25,c2p625,c3p5,c25,
     *     c29,c90,c100,c10000,c1pd6
     *     /2.0d-6,1.0d-4,1.0d-1,2.0d-1,2.5d-1,5.0d-1,1.5d0,2.25d0,
     *      2.625d0,3.5d0,2.5d1,2.9d1,9.0d1,1.0d2,1.0d4,1.0d6/
      data ap /1.0d-5/
      data y(1),y(2),y(3),y(4),y(5),y(6),y(7),y(8),y(9),y(10),y(11),
     *     y(12),y(13),y(14),y(15)
     *     /9.0d-4,4.4d-3,1.75d-2,5.4d-2,1.295d-1,2.42d-1,3.521d-1,
     *      3.989d-1,3.521d-1,2.42d-1,1.295d-1,5.4d-2,1.75d-2,4.4d-3,
     *      9.0d-4/
c
c     Function routine selector.
c
      go to (10,20,40,60,70,90,110,150,170,200,210,230,250,280,300,
     *       320,330,340), nprob
c
c     Helical valley function.
c
   10 continue
      tpi = eight*atan(one)
      th = sign(cp25,x(2))
      if (x(1) .gt. zero) th = atan(x(2)/x(1))/tpi
      if (x(1) .lt. zero) th = atan(x(2)/x(1))/tpi + cp5
      arg = x(1)**2 + x(2)**2
      r = sqrt(arg)
      t = x(3) - ten*th
      f = c100*(t**2 + (r - one)**2) + x(3)**2
      return
c
c     Biggs exp6 function.
c
   20 continue
      f = zero
      do 30 i = 1, 13
         d1 = dble(i)/ten
         d2 = exp(-d1) - five*exp(-ten*d1) + three*exp(-four*d1)
         s1 = exp(-d1*x(1))
         s2 = exp(-d1*x(2))
         s3 = exp(-d1*x(5))
         t = x(3)*s1 - x(4)*s2 + x(6)*s3 - d2
         f = f + t**2
   30    continue
      return
c
c     Gaussian function.
c
   40 continue
      f = zero
      do 50 i = 1, 15
         d1 = cp5*dble(i-1)
         d2 = c3p5 - d1 - x(3)
         arg = -cp5*x(2)*d2**2
         r = exp(arg)
         t = x(1)*r - y(i)
         f = f + t**2
   50    continue
      return
c
c     Powell badly scaled function.
c
   60 continue
      t1 = c10000*x(1)*x(2) - one
      s1 = exp(-x(1))
      s2 = exp(-x(2))
      t2 = s1 + s2 - one - cp0001
      f = t1**2 + t2**2
      return
c
c     Box 3-dimensional function.
c
   70 continue
      f = zero
      do 80 i = 1, 10
         d1 = dble(i)
         d2 = d1/ten
         s1 = exp(-d2*x(1))
         s2 = exp(-d2*x(2))
         s3 = exp(-d2) - exp(-d1)
         t = s1 - s2 - s3*x(3)
         f = f + t**2
   80    continue
      return
c
c     Variably dimensioned function.
c
   90 continue
      t1 = zero
      t2 = zero
      do 100 j = 1, n
         t1 = t1 + dble(j)*(x(j) - one)
         t2 = t2 + (x(j) - one)**2
  100    continue
      f = t2 + t1**2*(one + t1**2)
      return
c
c     Watson function.
c
  110 continue
      f = zero
      do 140 i = 1, 29
         d1 = dble(i)/c29
         s1 = zero
         d2 = one
         do 120 j = 2, n
            s1 = s1 + dble(j-1)*d2*x(j)
            d2 = d1*d2
  120       continue
         s2 = zero
         d2 = one
         do 130 j = 1, n
            s2 = s2 + d2*x(j)
            d2 = d1*d2
  130       continue
         t = s1 - s2**2 - one
         f = f + t**2
  140    continue
      t1 = x(2) - x(1)**2 - one
      f = f + x(1)**2 + t1**2
      return
c
c     Penalty function I.
c
  150 continue
      t1 = -cp25
      t2 = zero
      do 160 j = 1, n
         t1 = t1 + x(j)**2
         t2 = t2 + (x(j) - one)**2
  160    continue
      f = ap*t2 + t1**2
      return
c
c     Penalty function II.
c
  170 continue
      t1 = -one
      t2 = zero
      t3 = zero
      d1 = exp(cp1)
      d2 = one
      do 190 j = 1, n
         t1 = t1 + dble(n-j+1)*x(j)**2
         s1 = exp(x(j)/ten)
         if (j .gt. 1) then
            s3 = s1 + s2 - d2*(d1 + one)
            t2 = t2 + s3**2
            t3 = t3 + (s1 - one/d1)**2
            end if
         s2 = s1
         d2 = d1*d2
  190    continue
      f = ap*(t2 + t3) + t1**2 + (x(1) - cp2)**2
      return
c
c     Brown badly scaled function.
c
  200 continue
      t1 = x(1) - c1pd6
      t2 = x(2) - c2pdm6
      t3 = x(1)*x(2) - two
      f = t1**2 + t2**2 + t3**2
      return
c
c     Brown and Dennis function.
c
  210 continue
      f = zero
      do 220 i = 1, 20
         d1 = dble(i)/five
         d2 = sin(d1)
         t1 = x(1) + d1*x(2) - exp(d1)
         t2 = x(3) + d2*x(4) - cos(d1)
         t = t1**2 + t2**2
         f = f + t**2
  220    continue
      return
c
c     Gulf research and development function.
c
  230 continue
      f = zero
      d1 = two/three
      do 240 i = 1, 99
         arg = dble(i)/c100
         r = (-fifty*log(arg))**d1 + c25 - x(2)
         t1 = abs(r)**x(3)/x(1)
         t2 = exp(-t1)
         t = t2 - arg
         f = f + t**2
  240    continue
      return
c
c     Trigonometric function.
c
  250 continue
      s1 = zero
      do 260 j = 1, n
         s1 = s1 + cos(x(j))
  260    continue
      f = zero
      do 270 j = 1, n
         t = dble(n+j) - sin(x(j)) - s1 - dble(j)*cos(x(j))
         f = f + t**2
  270    continue
      return
c
c     Extended Rosenbrock function.
c
  280 continue
      f = zero
      do 290 j = 1, n, 2
         t1 = one - x(j)
         t2 = ten*(x(j+1) - x(j)**2)
         f = f + t1**2 + t2**2
  290    continue
      return
c
c     Extended Powell function.
c
  300 continue
      f = zero
      do 310 j = 1, n, 4
         t = x(j) + ten*x(j+1)
         t1 = x(j+2) - x(j+3)
         s1 = five*t1
         t2 = x(j+1) - two*x(j+2)
         s2 = t2**3
         t3 = x(j) - x(j+3)
         s3 = ten*t3**3
         f = f + t**2 + s1*t1 + s2*t2 + s3*t3
  310    continue
      return
c
c     Beale function.
c
  320 continue
      s1 = one - x(2)
      t1 = c1p5 - x(1)*s1
      s2 = one - x(2)**2
      t2 = c2p25 - x(1)*s2
      s3 = one - x(2)**3
      t3 = c2p625 - x(1)*s3
      f = t1**2 + t2**2 + t3**2
      return
c
c     Wood function.
c
  330 continue
      s1 = x(2) - x(1)**2
      s2 = one - x(1)
      s3 = x(2) - one
      t1 = x(4) - x(3)**2
      t2 = one - x(3)
      t3 = x(4) - one
      f = c100*s1**2 + s2**2 + c90*t1**2 + t2**2 + ten*(s3 + t3)**2
     *    + (s3 - t3)**2/ten
      return
c
c     Chebyquad function.
c
  340 continue
      do 350 i = 1, n
         fvec(i) = zero
  350    continue
      do 370 j = 1, n
         t1 = one
         t2 = two*x(j) - one
         t = two*t2
         do 360 i = 1, n
            fvec(i) = fvec(i) + t2
            th = t*t2 - t1
            t1 = t2
            t2 = th
  360       continue
  370    continue
      f = zero
      d1 = one/dble(n)
      iev = -1
      do 380 i = 1, n
         t = d1*fvec(i)
         if (iev .gt. 0) t = t + one/(dble(i)**2 - one)
         f = f + t**2
         iev = -iev
  380    continue
      return
c
c     Last card of subroutine objfcn.
c
      end
