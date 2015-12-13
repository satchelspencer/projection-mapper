# Problem Set 4

### (1) FMS Attack
Javascript source (nodejs for asycronous control flow)
~~~ Javascript
var async = require('async');
var net = require('net');
var _ = require('underscore');

function bytesToHex(bytes){
	return _.map(bytes, function(byte){
		return (byte<15?'0':'')+byte.toString(16)
	}).join(' ').toUpperCase();
}

/* query server for first output byte given IV (3 byte array)
   callback with first byte of RC4 stream */
function getFirstByte(iv, callback){
	var client = new net.Socket();
	client.connect(31416, 'hitchens.cs.colorado.edu', function() {
		client.write(bytesToHex(iv)+'\n'); //format as 'XX XX XX' and send
	});
	client.on('data', function(raw){
		callback(parseInt(raw)^0xaa); //xor with known header
	});
}

/* run through the first steps of KSA to find probable keybyte */
function findNextByte(knownKey, out){
	var s = [];
	var l = knownKey.length;
	for(var i = 0;i<256;i++) s.push(i);
	var j = 0;
	for(var i = 0;i<l;i++){ //only iterate knownKey length number of times
		j = (j+s[i]+knownKey[i%l])%256;
		var t = s[j];
		s[j] = s[i];
		s[i] = t;
	}
	return (out-s[l]-s[l-1]+256)%256; //undo the first byte of output generated
}

/* reduce over each of the 5 unkown keybytes, building the known key as we go along */
async.reduce(_.range(5), [3,255,1], function(knownKey, keyindex, callback){
	console.log('known key:', _.rest(knownKey, 3));
	knownKey[0] = 3+keyindex; //set as 'a+3' to find keyByte 'keyIndex'
	/* test all possible IVs with given format [a+3, 255, x] */
	async.mapSeries(_.range(256), function(lbi, done){
		var possibleKey = knownKey.slice(0); //clone key
		possibleKey[2] = lbi;
		/* fetch output byte and compute probable next keyByte */
		getFirstByte(_.first(possibleKey, 3), function(firstByte){
			done(null, findNextByte(possibleKey, firstByte));
		});	
	}, function(e, outputBytes){
		/* outputBytes contains all possible next keyBytes */
		console.log('	got: ', _.uniq(outputBytes).join(','));
		var mostFrequent = _.chain(outputBytes).groupBy().max(function(group){
			return group.length;
		}).value()[0];
		console.log('	most frequent key byte:', mostFrequent)
		/* add to our known key and proceed to next keyByte */
		knownKey.push(mostFrequent); 
		callback(null, knownKey);
	});
	
}, function(e, key){
	console.log('known key:', _.rest(key, 3));
	/* last 5 bytes is the secret key */
	var secret = _.last(key, 5);
	console.log(bytesToHex(secret));
})
~~~
result
~~~
known key: []
	got:  30,160,222,250,75,153,192,2,99,34,9,254,14,52,252,149,178,183,131,124,70,232,193,151,92,157,26,211,172,64,233,38,239,126,197,101,238,108,44,4,5,112,188,13,201,190,244,69,182,212,39,189,6,143,228,109,63,216,28,80,1,203,93,45,18,15,177,176,37,87,8,159,136,60,247,61,251,163,111,236,50,10,202,174,214,229,191,171,49,20,235,200,53,180,213,155,199,100,119,35,168,146,19,224,164,147,115,207,205,230,194,48,68,29,104,89,133,107,154,144,16,24,142,152,118,195,55,206,32,23,242,162,220,166,102,225,156,77,97,248,95,134,46,179,42,11,255,59,113,127,196,208,184,240,226,54,22,165,86,98,120,12,148,150,186,106,217,140,125,117
	most frequent key byte: 222
known key: [ 222 ]
	got:  50,113,244,222,173,62,254,207,117,44,122,132,212,179,141,70,10,127,26,68,64,102,51,239,78,104,135,192,168,204,171,223,150,45,185,237,73,241,5,49,20,93,9,115,200,97,203,214,83,77,136,1,82,160,114,123,142,146,60,194,133,84,137,202,57,153,199,250,147,47,162,205,167,56,221,80,229,0,174,24,155,91,170,201,8,35,175,236,218,40,217,182,129,13,238,180,226,206,29,19,253,76,121,215,128,21,66,193,23,111,118,36,190,28,172,74,197,140,184,16,7,25,148,32,110,124,18,138,34,156,196,209,181,251,11,125,95,86,14,31,248,52,198,163,188,161,177,208,33,53,165,2
	most frequent key byte: 173
known key: [ 222, 173 ]
	got:  38,190,9,42,72,113,184,66,218,105,147,188,51,174,1,233,24,181,235,33,158,78,118,82,80,115,244,92,219,139,29,14,171,179,225,95,213,62,145,124,128,127,43,159,180,253,97,150,7,48,232,121,87,40,91,153,41,241,247,203,226,116,117,22,94,189,93,154,170,148,236,60,135,214,13,104,112,47,81,0,31,223,109,138,49,46,65,131,201,67,136,196,39,71,86,141,162,224,70,73,55,251,252,99,53,250,44,234,156,248,56,12,77,245,186,215,32,177,28,8,168,106,206,216,237,182,23,54,163,205,173,132,126,198,192,183,209,85,50,68,246,142,239,10,25,30,88,165,5,134,204,83,194,4,240,58,11,122
	most frequent key byte: 190
known key: [ 222, 173, 190 ]
	got:  252,26,152,38,182,160,39,236,185,87,137,106,167,28,24,61,109,159,7,92,120,217,175,134,29,239,191,95,93,213,118,18,148,133,102,229,238,21,248,86,254,73,206,208,70,242,5,116,99,111,226,72,84,174,114,147,74,42,41,67,52,107,30,138,63,119,165,68,94,25,142,115,54,255,2,77,80,69,51,108,8,64,123,117,247,40,212,154,223,237,44,104,249,187,6,235,60,79,55,23,36,31,85,122,163,214,78,207,37,241,177,209,143,144,12,188,173,4,146,166,1,153,129,128,196,10,81,150,251,43,90,89,250,71,9,198,183,232,82,76,49,100,130,91,83,22,178,245,197,211,105,14,161,168,220,190
	most frequent key byte: 239
known key: [ 222, 173, 190, 239 ]
	got:  153,151,97,18,99,199,157,106,73,172,119,109,58,202,231,71,10,32,43,74,229,224,171,169,11,51,8,35,165,159,0,147,177,235,238,29,40,44,158,95,137,249,116,230,113,245,145,174,187,27,123,107,55,193,152,216,110,213,217,68,188,242,150,191,33,148,7,26,210,34,122,155,25,167,61,232,163,14,173,49,185,56,128,6,125,178,104,236,184,223,244,62,63,251,154,39,215,111,91,212,37,247,45,65,234,50,103,180,115,59,254,23,168,4,87,246,182,114,250,47,179,146,94,175,186,92,67,1,5,134,133,126,41,117,201,139,219,243,17,19,3,21,225,70,198,149,237,220,52,112,54,214,143,140,160,162,84,183,85,197,203,181,66,28,196
	most frequent key byte: 0
known key: [ 222, 173, 190, 239, 0 ]
DE AD BE EF 00
~~~

### (2) AES Hash
Because AES has the properties of a secure block cipher, this hashing scheme is inversion resistant. However collisions are somewhat of a worry, firstly because of the limited size of the output, when compared with widely used hashing algorhythms (sha-256 etc). Also, AES has some vulnerability to related key Cryptanalysis (http://www.impic.org/papers/Aes-192-256.pdf) which is problematic in this construction.

### (3) CMAC 
In CMAC if k1=k2 then the MAC is vulnerable to the same variable length attacks as CBC-MAC. To forge a message from alice the attacker must see the correct tag for two different length messages. A messaged can be forged by XORing the first block of the second message with the tag of the first and prepedning with the first message, this "inserts" into the CBC chain and authenticates an invalid message.

### (4) Modular Arithmetic
`4^1536 - 9^4824 mod 35`  
 - compute `4^1536 mod 35`
 
   power | value | %35
   ------|-------|------
   1     |4      |4
   2     |16      |16
   4     |256      |11
   8     |121      |16
   16    |256      |11
   32    |     |16
   64    |      |11
   128   |     |16
   256   |      |11
   512   |      |16
   1024  |      |11
 - 1536 can be expressed as `1024+512` so `4^1536 mod 35` = `11*16 mod 35` = `1 mod 35` 
 - compute `9^4824 mod 35`
 
   power | value | %35
   ------|-------|------
   1     |9      |9
   2     |81      |11
   4     |121      |16
   8     |256      |11
   16    |121      |16
   32    |     |11
   64    |      |16
   128   |     |11
   256   |      |16
   512   |      |11
   1024  |      |16
   2048  |      |11
   4096  |      |16
 - `4824` is `4096` with `728` remaining
 - `728` is `512` with `214` remaining
 - `214` is `128` with `86` remaining
 - `86` is `64` with `22` remaining
 - `22` is `16` with `8` remaining
 - `4824 = 4096+512+128+64+16+8` multiply because exponents: `(16*11)*(11*16)*(11*16)`
 - we know `11*16 mod 35 = 1` so `9^4824 mod 35 = 1*1*1 = 1`
 - `4^1536 - 9^4824 mod 35 = 1-1 = 0`

`2^2^2012 mod 3`
 - `4^2012 mod 3`
   
   power | value | %3
   ------|-------|------
   1     |4      |1
   2     |1      |1
   1024  |      |1
 - since 2012 can be expressed a sum of powers of two and all 4 to powers of two mod 3 are 1, `2^2^2012 mod 3 = 1`
 
`5^30000 - 6^123456 mod 31`
 - first compute `5^30000`
   
   power | value | %31
   ------|-------|------
   1     |5      |5
   2     |25      |25
   4     |625      |5
   8     |      |25
   16    |      |5
   32    |     |25
   64    |      |5
   128   |     |25
   256   |      |5
   512   |      |25
   1024  |      |5
   2048  |      |25
   4096  |      |5
   8192  |      |25
   16384  |      |5
   - `30000` is `16384` with `13616` remaining
   - `13616` is `8192` with `5424` remaining
   - `5424` is `4096` with `1328` remaining
   - `1328` is `1024` with `304` remaining
   - `304` is `256` with `48` remaining 
   - `48` is `32` with `16` remaining
   - `30000 = 16384+8192+4096+1024+256+32+16`
   - `5^30000 mod 31 = 5*25*(5*5)*5*25*5 mod 31 = (25*25)*(25*25)*5 mod 31`
   - we already know `(25*25) mod 31 = 5` so `5^30000 mod 31 = 25*5 mod 31 = 1`
 - now compute `6^123456`
   
   power | value | %31
   ------|-------|------
   1     |6      |6
   2     |36      |5
   4     |25      |25
   8     |625      |5
   16    |      |25
   32    |     |5
   64    |      |25
   128   |     |5
   256   |      |25
   512   |      |5
   1024  |      |25
   2048  |      |5
   4096  |      |25
   8192  |      |5
   16384  |      |25
   32768|      |5
   65536|      |25
   - `123456` is `65536` with `57920` remaining
   - `57920` is `32768` with `25152` remaining
   - `25152` is `16384` with `8768` remaining
   - `8768` is `8192` with `576` remaining
   - `576` is `512` with `64` remaining 
 - `123456 is 65536+32768+16384+8192+512+64`
 - `6^123456 mod 31 = 25*5*25*5*5*25 mod 31 = 1`
 - `5^30000 - 6^123456 mod 31 = 1-1 mod 31 = 0`
 

 

### (5) Factor with totient
where n is the product of two primes p and q 
 - `φ(n) = (p-1)(q-1)`
 - `φ(n) = pq-p-q+1`
 - `pq = n`
 - `φ(n) = n-p-q+1`
 - `n+1-φ(n) = p+q`
 - `n+1-φ(n) = (n/q)+q`
 - `n+1-φ(n) = (1+q^2)/q`
 - `q^2 + (n+1-φ(n))q + n = 0`
 - `q = (-(n+1-φ(n))+sqrt((n+1-φ(n))^2 + 4n))/2`

python implementation
~~~ Python
from decimal import *

def factor(n, phi):
	getcontext().prec = 1000
	b = Decimal(n+1-phi)
	q = (b+Decimal((b**2)-(4*n)).sqrt())/2
	return [q, n/q]
~~~

found factors
~~~
87616674126417466612535147492040019128471645126366689
17868162487124512745172458187648164182764812764187669
~~~

### (6) RSA Misused
 - since e1 and e2 are coprime we can find inverses `x,y such that x*e1+y*e2 = 1` with the extended euclidiean algorithm
 - `e1^x*e2^y = M mod n`
 
python implementation:
~~~ Python
def extendedEuclid(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extendedEuclid(b % a, a)
        return (g, x - (b // a) * y, y)

ct1 = 400030256839145194441034228199292487980894977737102147552044462667917219509871638663296814615652770720888715
ct2 = 48384876797138828670281479166255073593234801358795810198774095180850824157124747742456773738763877257747936
n = 640434271860669796692811836922138143942513719203565769421924022297363333847089887235971007435680486193657059
inv = extendedEuclid(65537, 65539)
print (pow(ct1,inv[1],n)*pow(ct2,inv[2]+n,n))%n 
~~~

output:
~~~
321279081050894212099873420148721147407647253778370013722534356594819460385825586617211817817458902529441531
~~~

### (7) RSA Misused again
since all are encrypted with a common exponent, we can simply use the Chineese Remainder theroem to find the solution for `m^3` for all the modulos then take the cube root to find the original message. python implementation:

~~~ Python
def crt(xs, mods):
    sum = 0
    prod = 1
    for mod in mods:
    	prod *= mod
    for mod, x in zip(mods, xs):
        p = prod / mod
        sum += x * extendedEuclid(p, mod)[1] * p
    return sum % prod

def nthroot(y, n):
    x, xp = 1, -1
    while abs(x - xp) > 1:
        xp, x = x, x - x/n + y/(n * x**(n-1))
    while x**n > y:
        x -= 1
    return x

c1 = 574452395725156603725695688076936855601594549917411892612661500787202925737746956998142588843598927541307873
c2 = 157799431549267581575022849850021876954972454961344389727981466349950578703950787569169912210813476301757037
c3 = 1848671214004714263512366793855069416003446215915866195803968453211062458759760233785518410532828930680295567
n1 = 640434271860669796692811836922138143942513719203565769421924022297363333847089887235971007435680486193657059
n2 = 970610447613980908168266345601001865862432914739686622721960687979888335326226411299703360406834787532308393
n3 = 2321625335993129657405265059789425474902906067465969731457920057903793687659258018704876705247348282139683997

expd = crt([c1,c2,c3], [n1,n2,n3]);

print nthroot(expd, 3)
~~~
 
output:
~~~
111111111111111111111111111111111111111111999999999999999999999999999999999999
~~~
