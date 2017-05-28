      subroutine vecfcn(n,x,fvec,nprob)
      integer n,nprob
      double precision x(n),fvec(n)
c     **********
c
c     subroutine vecfcn
c
c     This subroutine defines fourteen test functions. The first
c     five test functions are of dimensions 2,4,2,4,3, respectively,
c     while the remaining test functions are of variable dimension
c     n for any n greater than or equal to 1 (problem 6 is an
c     exception to this, since it does not allow n = 1).
c
c     The subroutine statement is
c
c       subroutine vecfcn(n,x,fvec,nprob)
c
c     where
c
c       n is a positive integer input variable.
c
c       x is an input array of length n.
c
c       fvec is an output array of length n which contains the nprob
c         function vector evaluated at x.
c
c       nprob is a positive integer input variable which defines the
c         number of the problem. nprob must not exceed 14.
c
c     Subprograms called
c
c       FORTRAN-supplied ... atan,cos,dble,exp,max,min,sign,sin,sqrt
c
c     Argonne National Laboratory. MINPACK Project. march 1980.
c     Burton S. Garbow, Kenneth E. Hillstrom, Jorge J. More
c
c     **********
      integer i,iev,j,k,ml,mu
      double precision c1,c2,c3,c4,c5,c6,c7,c8,c9,eight,five,h,one,
     *                 prod,sum,sum1,sum2,temp,temp1,temp2,ten,three,
     *                 ti,tj,tk,tpi,two,zero
      data zero,one,two,three,five,eight,ten
     *     /0.0d0,1.0d0,2.0d0,3.0d0,5.0d0,8.0d0,1.0d1/
      data c1,c2,c3,c4,c5,c6,c7,c8,c9
     *     /1.0d4,1.0001d0,2.0d2,2.02d1,1.98d1,1.8d2,2.5d-1,5.0d-1,
     *      2.9d1/
c
c     Problem selector.
c
      go to (10,20,30,40,50,60,120,170,200,220,270,300,330,350), nprob
c
c     Rosenbrock function.
c
   10 continue
      fvec(1) = one - x(1)
      fvec(2) = ten*(x(2) - x(1)**2)
      return
c
c     Powell singular function.
c
   20 continue
      fvec(1) = x(1) + ten*x(2)
      fvec(2) = sqrt(five)*(x(3) - x(4))
      fvec(3) = (x(2) - two*x(3))**2
      fvec(4) = sqrt(ten)*(x(1) - x(4))**2
      return
c
c     Powell badly scaled function.
c
   30 continue
      fvec(1) = c1*x(1)*x(2) - one
      fvec(2) = exp(-x(1)) + exp(-x(2)) - c2
      return
c
c     Wood function.
c
   40 continue
      temp1 = x(2) - x(1)**2
      temp2 = x(4) - x(3)**2
      fvec(1) = -c3*x(1)*temp1 - (one - x(1))
      fvec(2) = c3*temp1 + c4*(x(2) - one) + c5*(x(4) - one)
      fvec(3) = -c6*x(3)*temp2 - (one - x(3))
      fvec(4) = c6*temp2 + c4*(x(4) - one) + c5*(x(2) - one)
      return
c
c     Helical valley function.
c
   50 continue
      tpi = eight*atan(one)
      temp1 = sign(c7,x(2))
      if (x(1) .gt. zero) temp1 = atan(x(2)/x(1))/tpi
      if (x(1) .lt. zero) temp1 = atan(x(2)/x(1))/tpi + c8
      temp2 = sqrt(x(1)**2+x(2)**2)
      fvec(1) = ten*(x(3) - ten*temp1)
      fvec(2) = ten*(temp2 - one)
      fvec(3) = x(3)
      return
c
c     Watson function.
c
   60 continue
      do 70 k = 1, n
         fvec(k) = zero
   70    continue
      do 110 i = 1, 29
         ti = dble(i)/c9
         sum1 = zero
         temp = one
         do 80 j = 2, n
            sum1 = sum1 + dble(j-1)*temp*x(j)
            temp = ti*temp
   80       continue
         sum2 = zero
         temp = one
         do 90 j = 1, n
            sum2 = sum2 + temp*x(j)
            temp = ti*temp
   90       continue
         temp1 = sum1 - sum2**2 - one
         temp2 = two*ti*sum2
         temp = one/ti
         do 100 k = 1, n
            fvec(k) = fvec(k) + temp*(dble(k-1) - temp2)*temp1
            temp = ti*temp
  100       continue
  110    continue
      temp = x(2) - x(1)**2 - one
      fvec(1) = fvec(1) + x(1)*(one - two*temp)
      fvec(2) = fvec(2) + temp
      return
c
c     Chebyquad function.
c
  120 continue
      do 130 k = 1, n
         fvec(k) = zero
  130    continue
      do 150 j = 1, n
         temp1 = one
         temp2 = two*x(j) - one
         temp = two*temp2
         do 140 i = 1, n
            fvec(i) = fvec(i) + temp2
            ti = temp*temp2 - temp1
            temp1 = temp2
            temp2 = ti
  140       continue
  150    continue
      tk = one/dble(n)
      iev = -1
      do 160 k = 1, n
         fvec(k) = tk*fvec(k)
         if (iev .gt. 0) fvec(k) = fvec(k) + one/(dble(k)**2 - one)
         iev = -iev
  160    continue
      return
c
c     Brown almost-linear function.
c
  170 continue
      sum = -dble(n+1)
      prod = one
      do 180 j = 1, n
         sum = sum + x(j)
         prod = x(j)*prod
  180    continue
      do 190 k = 1, n-1
         fvec(k) = x(k) + sum
  190    continue
      fvec(n) = prod - one
      return
c
c     Discrete boundary value function.
c
  200 continue
      h = one/dble(n+1)
      do 210 k = 1, n
         temp = (x(k) + dble(k)*h + one)**3
         temp1 = zero
         if (k .ne. 1) temp1 = x(k-1)
         temp2 = zero
         if (k .ne. n) temp2 = x(k+1)
         fvec(k) = two*x(k) - temp1 - temp2 + temp*h**2/two
  210    continue
      return
c
c     Discrete integral equation function.
c
  220 continue
      h = one/dble(n+1)
      do 260 k = 1, n
         tk = dble(k)*h
         sum1 = zero
         do 230 j = 1, k
            tj = dble(j)*h
            temp = (x(j) + tj + one)**3
            sum1 = sum1 + tj*temp
  230       continue
         sum2 = zero
         do 240 j = k+1, n
            tj = dble(j)*h
            temp = (x(j) + tj + one)**3
            sum2 = sum2 + (one - tj)*temp
  240       continue
         fvec(k) = x(k) + h*((one - tk)*sum1 + tk*sum2)/two
  260    continue
      return
c
c     Trigonometric function.
c
  270 continue
      sum = zero
      do 280 j = 1, n
         fvec(j) = cos(x(j))
         sum = sum + fvec(j)
  280    continue
      do 290 k = 1, n
         fvec(k) = dble(n+k) - sin(x(k)) - sum - dble(k)*fvec(k)
  290    continue
      return
c
c     Variably dimensioned function.
c
  300 continue
      sum = zero
      do 310 j = 1, n
         sum = sum + dble(j)*(x(j) - one)
  310    continue
      temp = sum*(one + two*sum**2)
      do 320 k = 1, n
         fvec(k) = x(k) - one + dble(k)*temp
  320    continue
      return
c
c     Broyden tridiagonal function.
c
  330 continue
      do 340 k = 1, n
         temp = (three - two*x(k))*x(k)
         temp1 = zero
         if (k .ne. 1) temp1 = x(k-1)
         temp2 = zero
         if (k .ne. n) temp2 = x(k+1)
         fvec(k) = temp - temp1 - two*temp2 + one
  340    continue
      return
c
c     Broyden banded function.
c
  350 continue
      ml = 5
      mu = 1
      do 370 k = 1, n
         temp = zero
         do 360 j = max(1,k-ml),min(k+mu,n)
            if (j .ne. k) temp = temp + x(j)*(one + x(j))
  360       continue
         fvec(k) = x(k)*(two + five*x(k)**2) + one - temp
  370    continue
  380 continue
      return
c
c     Last card of subroutine vecfcn.
c
      end
