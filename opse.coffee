# Order Preserving Symmetric Encryption (OPSE)
#
# Encrypts numeric values in such a way that their original value is
# confidential, but inequalities can be performed on numbers encrypted under the
# same key.
crypto = require 'crypto'
{BigDecimal} = require 'bigdecimal'
{BigInteger} = require 'bigdecimal'

# Encrypt a number.
#
# 1. `key` is a random symmetric cipher key, in the form of
#    `caesar.key.createRandom()`.
# 2. `num` is a 16 bit number to encrypt.
exports.encrypt = (key, num) ->
    top = 131072
    cursor = 65536
    bottom = 0
    
    while true # Narrow search down.
        k = rhyper key, 65536, 65536, cursor
        
        if Math.abs(num - k) < 20 then break
        if num > k then bottom = cursor
        if num < k then top = cursor
        
        if cursor % 4 is 1
            cursor = Math.floor((top + bottom) / 2)
        else if cursor % 4 is 3
            cursor = Math.ceil((top + bottom) / 2)
        else
            cursor = (top + bottom) / 2
    
    ocursor = cursor + 20 # Get as accurate as possible.
    if k > num then cursor -= 80
    if cursor < 0 then cursor = 0
    bcursor = cursor
    
    okay = false
    while not okay and cursor <= ocursor
        cursor = cursor + 2
        k = rhyper key, 65536, 65536, cursor
        
        if k is num then okay = true
    
    if not okay
        while bcursor <= ocursor
            bcursor = bcursor + 2
            k = rhyper key, 65536, 65536, bcursor
            
            if k > num
                bcursor -= 1
                break
        
        cursor = bcursor
    
    cursor

# The following five functions have been ported from the R Project for
# Statistical Computing and appropriately modified.  Don't ask me how or why
# they work.
afc = (i) ->
    al =
	    0: '0' # ln(0!)=ln(1)
	    1: '0' # ln(1!)=ln(1)
	    2: '0.69314718055994530941723212145817' # ln(2)
	    3: '1.79175946922805500081247735838070' # ln(6)
	    4: '3.17805383034794561964694160129705' # ln(24)
	    5: '4.78749174278204599424770093452324'
	    6: '6.57925121201010099506017829290394'
	    7: '8.52516136106541430016553103634712'
	    8: '10.60460290274525022841722740072165'
    
    if i < 0 then throw 'i less than 0.  Should not happen.'
    if i <= 8 then return al[i]
    
    pi = 0.5 * Math.log(2 * Math.PI)
    (i+0.5) * Math.log(i) - i + (1/12) / i - (1/360) / i / i / i + pi

imax2 = (x, y) -> if x < y then y else x
imin2 = (x, y) -> if x < y then x else y

class PRNG
    constructor: (@coin) ->
        @cipher = crypto.createCipher 'aes-256-ctr', @coin
        @blank = new Buffer 16
        @blank.fill 0
    
    draw: ->
        @cipher.write @blank
        out = @cipher.read()
        
        numer = new BigInteger out.toString('hex'), 16
        numer = new BigDecimal numer.toString()
        denom = new BigDecimal '340282366920938463463374607431768211456'
        
        parseFloat numer.divide(denom, 100, BigDecimal.ROUND_HALF_UP).toString()

rhyper = (coin, nn1, nn2, kk) ->
    prng = new PRNG coin
    
    con = 57.56462733
    deltal = 0.0078
    deltau = 0.0034
    ks = -1
    n1s = -1
    n2s = -1
    scale = 1e25
    
    if nn1 is Infinity or nn2 is Infinity or kk is Infinity then throw 'NaN'
    
    nn1 = Math.floor(nn1 + 0.5)
    nn2 = Math.floor(nn2 + 0.5)
    kk = Math.floor(kk + 0.5)
    
    if nn1 < 0 or nn2 < 0 or kk < 0 or kk > (nn1 + nn2) then throw 'NaN'
    
    if nn1 isnt n1s or nn2 isnt n2s
        setup1 = true
        setup2 = true
    else if kk isnt ks
        setup1 = false
        setup2 = true
    else
        setup1 = false
        setup2 = false
    
    if setup1
        n1s = nn1
        n2s = nn2
        tn = nn1 + nn2
        
        if nn1 <= nn2
            n1 = nn1
            n2 = nn2
        else
            n1 = nn2
            n2 = nn1
    
    if setup2
        ks = kk
        tk = kk + kk
        
        if (kk + kk) >= tn
            k = tn - kk
        else
            k = kk
    
    if setup1 or setup2
        m = (k + 1) * (n1 + 1) / (tn + 2)
        
        minjx = imax2 0, (k - n2)
        maxjx = imin2 n1, k
    
    # Generate random variate -- three basic cases.
    
    if minjx is maxjx # I : Degenerate distribution.
        ix = maxjx
    else if (m - minjx) < 10 # II : Inverse transformation.
        if setup1 or setup2
            if k < n2
                w = Math.exp(con + afc(n2) + afc(n1 + n2 - k) - afc(n2 - k) - 
                    afc(n1 + n2))
            else
                w = Math.exp(con + afc(n1) + afc(k) - afc(k-n2) - afc(n1+n2))
        
        l10 = (w, minjx) -> # L10
            p = w
            ix = minjx
            u = prng.draw() * 1e25
            
            [p, ix, u]
        
        [p, ix, u] = l10 w, minjx
        
        while u > p # L20
            u -= p
            p *= (n1 - ix) * (k - ix)
            ++ix
            
            p = p / ix / (n2 - k + ix)
            if ix > maxjx then [p, ix, u] = l10 w, minjx
        
    else # III : h2pe
        if setup1 or setup2
            s = Math.sqrt((tn - k) * k * n1 * n2 / (tn - 1) / tn / tn)
            d = Math.floor((1.5 * s) + 0.5)
            xl = m - d + 0.5
            xr = m + d + 0.5
            a = afc(m) + afc(n1 - m) + afc(k - m) + afc(n2 - k + m)
            kl = Math.exp(a - afc(Math.floor(xl)) - afc(Math.floor(n1 - xl)) -
                afc(Math.floor(k - xl)) - afc(Math.floor(n2 - k + xl)))
            kr = Math.exp(a - afc(Math.floor(xr - 1)) -
                afc(Math.floor(n1 - xr + 1)) - afc(Math.floor(k - xr + 1)) -
                afc(Math.floor(n2 - k + xr - 1)))
            lamdl = -Math.log(xl * (n2 - k + xl) / (n1 - xl + 1) / (k - xl + 1))
            lamdr = -Math.log((n1 - xr + 1) * (k - xr + 1) / xr / (n2 - k + xr))
            p1 = d + d
            p2 = p1 + kl / lamdl
            p3 = p2 + kr / lamdr
        
        while true # L30
            u = prng.draw() * p3
            v = prng.draw()
            
            if u < p1
                ix = Math.floor(xl + u)
            else if (u <= p2)
                ix = Math.floor(xl + Math.log(v) / lamdl)
                if ix < minjx then continue
                v = v * (u - p1) * lamdl
            else
                ix = Math.floor(xr - Math.log(v) / lamdr)
                if ix > maxjx then continue
                v = v * (u - p2) * lamdr
            
            # Acceptance/Rejection Test
            if m < 100 or ix <= 50
                f = 1
                
                if m < ix
                    i = m + 1
                    
                    while i <= ix
                        f = f * (n1 - i + 1) * (k - i + 1) / (n2 - k + i) / i
                        ++i
                
                else if m > ix
                    i = ix + 1
                    
                    while i <= m
                        f = f * i * (n2 - k + i) / (n1 - i + 1) / (k - i + 1)
                        ++i
                
                if v <= f then break
            else
                # Squeeze using upper and lower bounds.
                y = ix
                y1 = y + 1
                ym = y - m
                yn = n1 - y + 1
                yk = k - y + 1
                nk = n2 - k + y1
                r = -ym / y1
                s = ym / yn
                t = ym / yk
                e = -ym / nk
                g = yn * yk / (y1 * nk) - 1
                dg = 1
                if g < 0 then dg = 1 + g
                
                gu = g * (1 + g * (-0.5 + g / 3))
                gl = gu - .25 * (g * g * g * g) / dg
                xm = m + 0.5
                xn = n1 - m + 0.5
                xk = k - m + 0.5
                nm = n2 - k + xm
                ub = y * gu - m * gl + deltau + 
                    xm * r * (1 + r * (-0.5 + r / 3)) + 
                    xn * s * (1 + s * (-0.5 + s / 3)) +
                    xk * t * (1 + t * (-0.5 + t / 3)) +
                    nm * e * (1 + e * (-0.5 + e / 3))
                
                # Test against upper bound.
                alv = Math.log v
                if alv > ub then continue
                
                # Test against lower bound.
                dr = xm * (r * r * r * r)
                if r < 0 then dr /= (1 + r)
                
                ds = xn * (s * s * s * s)
                if s < 0 then ds /= (1 + s)
                
                dt = xk * (t * t * t * t)
                if t < 0 then dt /= (1 + t)
                
                de = nm * (e * e * e * e)
                if e < 0 then de /= (1 + e)
                
                cand = ub - 0.25 * (dr+ds+dt+de) + (y + m) * (gl - gu) - deltal
                if alv < cand then break
                else
                    # Stirling's formula to machine accuracy
                    cand = (a - afc(ix) - afc(n1-ix) - afc(k-ix) - afc(n2-k+ix))
                    if alv <= cand then break else continue
    
    # Return appropriate variate.
    if (kk + kk) >= tn
        if nn1 > nn2
            ix = kk - nn2 + ix
        else ix = nn1 - ix
    else
        if nn1 > nn2
            ix = kk - ix
    
    ix
