      subroutine ssqfcn(m,n,x,fvec,nprob)
      integer m,n,nprob
      double precision x(n),fvec(m)
c     **********
c
c     subroutine ssqfcn
c
c     This subroutine defines the functions of eighteen nonlinear
c     least squares problems. The allowable values of (m,n) for
c     functions 1,2 and 3 are variable but with m .ge. n.
c     For functions 4,5,6,7,8,9 and 10 the values of (m,n) are
c     (2,2),(3,3),(4,4),(2,2),(15,3),(11,4) and (16,3), respectively.
c     Function 11 (Watson) has m = 31 with n usually 6 or 9.
c     However, any n, n = 2,...,31, is permitted.
c     Functions 12,13 and 14 have n = 3,2 and 4, respectively, but
c     allow any m .ge. n, with the usual choices being 10,10 and 20.
c     Function 15 (Chebyquad) allows m and n variable with m .ge. n.
c     Function 16 (Brown) allows n variable with m = n.
c     For functions 17 and 18, the values of (m,n) are
c     (33,5) and (65,11), respectively.
c
c     The subroutine statement is
c
c       subroutine ssqfcn(m,n,x,fvec,nprob)
c
c     where
c
c       m and n are positive integer input variables. n must not
c         exceed m.
c
c       x is an input array of length n.
c
c       fvec is an output array of length m which contains the nprob
c         function evaluated at x.
c
c       nprob is a positive integer input variable which defines the
c         number of the problem. nprob must not exceed 18.
c
c     Subprograms called
c
c       FORTRAN-supplied ... atan,cos,dble,exp,sign,sin,sqrt
c
c     Argonne National Laboratory. MINPACK Project. march 1980.
c     Burton S. Garbow, Kenneth E. Hillstrom, Jorge J. More
c
c     **********
      integer i,iev,j
      double precision c13,c14,c29,c45,div,dx,eight,five,one,prod,sum,
     *                 s1,s2,temp,ten,ti,tmp1,tmp2,tmp3,tmp4,tpi,two,
     *                 zero,zp25,zp5
      double precision v(11),y1(15),y2(11),y3(16),y4(33),y5(65)
      data zero,zp25,zp5,one,two,five,eight,ten,c13,c14,c29,c45
     *     /0.0d0,2.5d-1,5.0d-1,1.0d0,2.0d0,5.0d0,8.0d0,1.0d1,1.3d1,
     *      1.4d1,2.9d1,4.5d1/
      data v(1),v(2),v(3),v(4),v(5),v(6),v(7),v(8),v(9),v(10),v(11)
     *     /4.0d0,2.0d0,1.0d0,5.0d-1,2.5d-1,1.67d-1,1.25d-1,1.0d-1,
     *      8.33d-2,7.14d-2,6.25d-2/
      data y1(1),y1(2),y1(3),y1(4),y1(5),y1(6),y1(7),y1(8),y1(9),
     *     y1(10),y1(11),y1(12),y1(13),y1(14),y1(15)
     *     /1.4d-1,1.8d-1,2.2d-1,2.5d-1,2.9d-1,3.2d-1,3.5d-1,3.9d-1,
     *      3.7d-1,5.8d-1,7.3d-1,9.6d-1,1.34d0,2.1d0,4.39d0/
      data y2(1),y2(2),y2(3),y2(4),y2(5),y2(6),y2(7),y2(8),y2(9),
     *     y2(10),y2(11)
     *     /1.957d-1,1.947d-1,1.735d-1,1.6d-1,8.44d-2,6.27d-2,4.56d-2,
     *      3.42d-2,3.23d-2,2.35d-2,2.46d-2/
      data y3(1),y3(2),y3(3),y3(4),y3(5),y3(6),y3(7),y3(8),y3(9),
     *     y3(10),y3(11),y3(12),y3(13),y3(14),y3(15),y3(16)
     *     /3.478d4,2.861d4,2.365d4,1.963d4,1.637d4,1.372d4,1.154d4,
     *      9.744d3,8.261d3,7.03d3,6.005d3,5.147d3,4.427d3,3.82d3,
     *      3.307d3,2.872d3/
      data y4(1),y4(2),y4(3),y4(4),y4(5),y4(6),y4(7),y4(8),y4(9),
     *     y4(10),y4(11),y4(12),y4(13),y4(14),y4(15),y4(16),y4(17),
     *     y4(18),y4(19),y4(20),y4(21),y4(22),y4(23),y4(24),y4(25),
     *     y4(26),y4(27),y4(28),y4(29),y4(30),y4(31),y4(32),y4(33)
     *     /8.44d-1,9.08d-1,9.32d-1,9.36d-1,9.25d-1,9.08d-1,8.81d-1,
     *      8.5d-1,8.18d-1,7.84d-1,7.51d-1,7.18d-1,6.85d-1,6.58d-1,
     *      6.28d-1,6.03d-1,5.8d-1,5.58d-1,5.38d-1,5.22d-1,5.06d-1,
     *      4.9d-1,4.78d-1,4.67d-1,4.57d-1,4.48d-1,4.38d-1,4.31d-1,
     *      4.24d-1,4.2d-1,4.14d-1,4.11d-1,4.06d-1/
      data y5(1),y5(2),y5(3),y5(4),y5(5),y5(6),y5(7),y5(8),y5(9),
     *     y5(10),y5(11),y5(12),y5(13),y5(14),y5(15),y5(16),y5(17),
     *     y5(18),y5(19),y5(20),y5(21),y5(22),y5(23),y5(24),y5(25),
     *     y5(26),y5(27),y5(28),y5(29),y5(30),y5(31),y5(32),y5(33),
     *     y5(34),y5(35),y5(36),y5(37),y5(38),y5(39),y5(40),y5(41),
     *     y5(42),y5(43),y5(44),y5(45),y5(46),y5(47),y5(48),y5(49),
     *     y5(50),y5(51),y5(52),y5(53),y5(54),y5(55),y5(56),y5(57),
     *     y5(58),y5(59),y5(60),y5(61),y5(62),y5(63),y5(64),y5(65)
     *     /1.366d0,1.191d0,1.112d0,1.013d0,9.91d-1,8.85d-1,8.31d-1,
     *      8.47d-1,7.86d-1,7.25d-1,7.46d-1,6.79d-1,6.08d-1,6.55d-1,
     *      6.16d-1,6.06d-1,6.02d-1,6.26d-1,6.51d-1,7.24d-1,6.49d-1,
     *      6.49d-1,6.94d-1,6.44d-1,6.24d-1,6.61d-1,6.12d-1,5.58d-1,
     *      5.33d-1,4.95d-1,5.0d-1,4.23d-1,3.95d-1,3.75d-1,3.72d-1,
     *      3.91d-1,3.96d-1,4.05d-1,4.28d-1,4.29d-1,5.23d-1,5.62d-1,
     *      6.07d-1,6.53d-1,6.72d-1,7.08d-1,6.33d-1,6.68d-1,6.45d-1,
     *      6.32d-1,5.91d-1,5.59d-1,5.97d-1,6.25d-1,7.39d-1,7.1d-1,
     *      7.29d-1,7.2d-1,6.36d-1,5.81d-1,4.28d-1,2.92d-1,1.62d-1,
     *      9.8d-2,5.4d-2/
c
c     Function routine selector.
c
      go to (10,40,70,110,120,130,140,150,170,190,210,250,270,290,310,
     *       360,390,410), nprob
c
c     Linear function - full rank.
c
   10 continue
      sum = zero
      do 20 j = 1, n
         sum = sum + x(j)
   20    continue
      temp = two*sum/dble(m) + one
      do 30 i = 1, m
         fvec(i) = -temp
         if (i .le. n) fvec(i) = fvec(i) + x(i)
   30    continue
      return
c
c     Linear function - rank 1.
c
   40 continue
      sum = zero
      do 50 j = 1, n
         sum = sum + dble(j)*x(j)
   50    continue
      do 60 i = 1, m
         fvec(i) = dble(i)*sum - one
   60    continue
      return
c
c     Linear function - rank 1 with zero columns and rows.
c
   70 continue
      sum = zero
      do 80 j = 2, n-1
         sum = sum + dble(j)*x(j)
   80    continue
      do 100 i = 1, m-1
         fvec(i) = dble(i-1)*sum - one
  100    continue
      fvec(m) = -one
      return
c
c     Rosenbrock function.
c
  110 continue
      fvec(1) = ten*(x(2) - x(1)**2)
      fvec(2) = one - x(1)
      return
c
c     Helical valley function.
c
  120 continue
      tpi = eight*atan(one)
      tmp1 = sign(zp25,x(2))
      if (x(1) .gt. zero) tmp1 = atan(x(2)/x(1))/tpi
      if (x(1) .lt. zero) tmp1 = atan(x(2)/x(1))/tpi + zp5
      tmp2 = sqrt(x(1)**2+x(2)**2)
      fvec(1) = ten*(x(3) - ten*tmp1)
      fvec(2) = ten*(tmp2 - one)
      fvec(3) = x(3)
      return
c
c     Powell singular function.
c
  130 continue
      fvec(1) = x(1) + ten*x(2)
      fvec(2) = sqrt(five)*(x(3) - x(4))
      fvec(3) = (x(2) - two*x(3))**2
      fvec(4) = sqrt(ten)*(x(1) - x(4))**2
      return
c
c     Freudenstein and Roth function.
c
  140 continue
      fvec(1) = -c13 + x(1) + ((five - x(2))*x(2) - two)*x(2)
      fvec(2) = -c29 + x(1) + ((one + x(2))*x(2) - c14)*x(2)
      return
c
c     Bard function.
c
  150 continue
      do 160 i = 1, 15
         tmp1 = dble(i)
         tmp2 = dble(16-i)
         tmp3 = tmp1
         if (i .gt. 8) tmp3 = tmp2
         fvec(i) = y1(i) - (x(1) + tmp1/(x(2)*tmp2 + x(3)*tmp3))
  160    continue
      return
c
c     Kowalik and Osborne function.
c
  170 continue
      do 180 i = 1, 11
         tmp1 = v(i)*(v(i) + x(2))
         tmp2 = v(i)*(v(i) + x(3)) + x(4)
         fvec(i) = y2(i) - x(1)*tmp1/tmp2
  180    continue
      return
c
c     Meyer function.
c
  190 continue
      do 200 i = 1, 16
         temp = five*dble(i) + c45 + x(3)
         tmp1 = x(2)/temp
         tmp2 = exp(tmp1)
         fvec(i) = x(1)*tmp2 - y3(i)
  200    continue
      return
c
c     Watson function.
c
  210 continue
      do 240 i = 1, 29
         div = dble(i)/c29
         s1 = zero
         dx = one
         do 220 j = 2, n
            s1 = s1 + dble(j-1)*dx*x(j)
            dx = div*dx
  220       continue
         s2 = zero
         dx = one
         do 230 j = 1, n
            s2 = s2 + dx*x(j)
            dx = div*dx
  230       continue
         fvec(i) = s1 - s2**2 - one
  240    continue
      fvec(30) = x(1)
      fvec(31) = x(2) - x(1)**2 - one
      return
c
c     Box 3-dimensional function.
c
  250 continue
      do 260 i = 1, m
         temp = dble(i)
         tmp1 = temp/ten
         fvec(i) = exp(-tmp1*x(1)) - exp(-tmp1*x(2))
     *             + (exp(-temp) - exp(-tmp1))*x(3)
  260    continue
      return
c
c     Jennrich and Sampson function.
c
  270 continue
      do 280 i = 1, m
         temp = dble(i)
         fvec(i) = two + two*temp - exp(temp*x(1)) - exp(temp*x(2))
  280    continue
      return
c
c     Brown and Dennis function.
c
  290 continue
      do 300 i = 1, m
         temp = dble(i)/five
         tmp1 = x(1) + temp*x(2) - exp(temp)
         tmp2 = x(3) + sin(temp)*x(4) - cos(temp)
         fvec(i) = tmp1**2 + tmp2**2
  300    continue
      return
c
c     Chebyquad function.
c
  310 continue
      do 320 i = 1, m
         fvec(i) = zero
  320    continue
      do 340 j = 1, n
         tmp1 = one
         tmp2 = two*x(j) - one
         temp = two*tmp2
         do 330 i = 1, m
            fvec(i) = fvec(i) + tmp2
            ti = temp*tmp2 - tmp1
            tmp1 = tmp2
            tmp2 = ti
  330       continue
  340    continue
      dx = one/dble(n)
      iev = -1
      do 350 i = 1, m
         fvec(i) = dx*fvec(i)
         if (iev .gt. 0) fvec(i) = fvec(i) + one/(dble(i)**2 - one)
         iev = -iev
  350    continue
      return
c
c     Brown almost-linear function.
c
  360 continue
      sum = -dble(n+1)
      prod = one
      do 370 j = 1, n
         sum = sum + x(j)
         prod = x(j)*prod
  370    continue
      do 380 i = 1, n-1
         fvec(i) = x(i) + sum
  380    continue
      fvec(n) = prod - one
      return
c
c     Osborne 1 function.
c
  390 continue
      do 400 i = 1, 33
         temp = ten*dble(i-1)
         tmp1 = exp(-x(4)*temp)
         tmp2 = exp(-x(5)*temp)
         fvec(i) = y4(i) - (x(1) + x(2)*tmp1 + x(3)*tmp2)
  400    continue
      return
c
c     Osborne 2 function.
c
  410 continue
      do 420 i = 1, 65
         temp = dble(i-1)/ten
         tmp1 = exp(-x(5)*temp)
         tmp2 = exp(-x(6)*(temp-x(9))**2)
         tmp3 = exp(-x(7)*(temp-x(10))**2)
         tmp4 = exp(-x(8)*(temp-x(11))**2)
         fvec(i) = y5(i)
     *             - (x(1)*tmp1 + x(2)*tmp2 + x(3)*tmp3 + x(4)*tmp4)
  420    continue
      return
c
c     Last card of subroutine ssqfcn.
c
      end
