package main

import (
	"math/big"
	"crypto/sha256"
	crand "crypto/rand"
	"crypto/elliptic"
	"io"
	"bytes"

	"fmt"

	"math/rand"


)


var c elliptic.Curve
var one = new(big.Int).SetInt64(1)
var LimitHashLen = new(big.Int).SetInt64(1024)
type Public struct {
	elliptic.Curve
	x *big.Int
	y *big.Int
}

type RingSign struct {
	c0 			*big.Int
	r 	  		[]*big.Int
	yDashX 		*big.Int
	yDashY 		*big.Int
}

type PublicKeyRing struct {
	Ring []Public
}

type Private struct {
	D *big.Int
}

func (r *PublicKeyRing) Bytes() (b []byte) {
	for _, pub := range r.Ring {
		b = append(b, pub.x.Bytes()...)
		b = append(b, pub.y.Bytes()...)
	}
	return
}
func (r *PublicKeyRing) Len() (int){
	return len(r.Ring)
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func hashP(input []byte, c elliptic.Curve)(*big.Int, *big.Int){
	tmx, tmy := c.ScalarBaseMult(hashN(input).Bytes())
	return tmx, tmy
}

func hashN(input []byte) *big.Int{
	h := sha256.New()
	h.Write(input)
	output := new(big.Int).SetBytes(h.Sum(nil))
	output.Mod(output, LimitHashLen)
	return output
}

func sign(rand io.Reader, R *PublicKeyRing, m []byte, priv Private, index int) (*RingSign, error){
	var buffer bytes.Buffer
	len := R.Len()   //环长度
	priKey := priv.D	//用户私钥
	curve := R.Ring[0].Curve
//	N := curve.Params().N
	//步骤一
	hPX, hPY := hashP(R.Bytes(), curve)
	KDashX, KDashY := curve.ScalarMult(hPX, hPY, priKey.Bytes()) //公钥镜像， 验证链接性
	//步骤二
	c := make([]*big.Int, len)
	r := make([]*big.Int, len)
	for i := 0; i < len; i++{
		c[i] = new(big.Int)
		r[i] = new(big.Int)
	}
	a, err := randFieldElement(curve, rand) //随机数
	if err != nil {
		return  nil, err
	}
	//步骤三
	buffer.Write(R.Bytes())
	buffer.Write(KDashX.Bytes())
	buffer.Write(KDashY.Bytes())
	buffer.Write(m)
	aGX, aGY := curve.ScalarBaseMult(a.Bytes())
	fmt.Printf("aGx=%d; aGy=%d\n", aGX, aGY)
	buffer.Write(aGX.Bytes())
	buffer.Write(aGY.Bytes())

	aHpRX, aHpRY := curve.ScalarMult(hPX, hPY, a.Bytes())
	fmt.Printf("aHpRX=%d; aHpRY=%d\n", aHpRX, aHpRY)
	buffer.Write(aHpRX.Bytes())
	buffer.Write(aHpRY.Bytes())
	c[index % len] = hashN(buffer.Bytes())
	fmt.Printf("c[2]=%d\n", c[2])
	buffer.Reset()

	//步骤四
	for i := (index) % len; i != index - 1; i = (i + 1) % len{
		r[i], err = randFieldElement(curve, rand)
		buffer.Write(R.Bytes())
		buffer.Write(KDashX.Bytes())
		buffer.Write(KDashY.Bytes())
		buffer.Write(m)

		rGX, rGY := curve.ScalarBaseMult(r[i].Bytes())
		cKX, cKY := curve.ScalarMult(R.Ring[i].x, R.Ring[i].y, c[i].Bytes())
		rGcKX, rGcKY := curve.Add(rGX, rGY, cKX, cKY)
		buffer.Write(rGcKX.Bytes())
		buffer.Write(rGcKY.Bytes())

		rHpX, rHpY := curve.ScalarMult(hPX, hPY, r[i].Bytes())
		cKDashX, xKDashY := curve.ScalarMult(KDashX, KDashY, c[i].Bytes())
		rHpcKDashX, rHpcKDashY := curve.Add(rHpX, rHpY, cKDashX, xKDashY)
		buffer.Write(rHpcKDashX.Bytes())
		buffer.Write(rHpcKDashY.Bytes())
		if i == len-1{
			c[0] = hashN(buffer.Bytes())
			fmt.Printf("c[0]=%d\n", c[0])
		}else{
			c[i+1] = hashN(buffer.Bytes())
			fmt.Printf("c[%d]=%d\n",i+1, c[i+1])
		}
		buffer.Reset()

	}
	temp := new(big.Int)
	aModN := new(big.Int)
	temp.Mul(priKey, c[index-1])
	aModN.Sub(a, temp)

	r[index-1] = aModN
//###############################测试##################################
/*	testX, testY := curve.ScalarBaseMult(r[1].Bytes())
	fmt.Printf("testX=%d, testY=%d\n", testX, testY)
	fmt.Printf("r[1]=%d\n", r[1])

	tempX, tempY := curve.ScalarBaseMult(temp.Bytes())
	fmt.Printf("tempX=%d, tempY=%d\n", tempX, tempY)

	ck1X, ck1Y := curve.ScalarMult(R.Ring[1].x, R.Ring[1].y, c[1].Bytes())
	fmt.Printf("tempX=%d, tempY=%d\n", ck1X, ck1Y)*/
//	return c[0], r, KDashX, KDashY, nil
	return &RingSign{
		c0: c[0],
		r: r,
		yDashX: KDashX,
		yDashY: KDashY,
	}, nil
}

func verify(rs *RingSign, R *PublicKeyRing, m []byte) bool{
	var buffer bytes.Buffer
	curve := R.Ring[0].Curve
	hPX, hPY := hashP(R.Bytes(), curve)
	//zi'和zi''
	ziX := new(big.Int)
	ziY := new(big.Int)
	ziDashX := new(big.Int)
	ziDashY := new(big.Int)
	C := new(big.Int).SetBytes(rs.c0.Bytes())
	fmt.Printf("r[1]=%d\n", rs.r[1])
	fmt.Printf("c[0]=%d\n", rs.c0)
	for i := 0; i < R.Len(); i++{
		rGX, rGY := curve.ScalarBaseMult(rs.r[i].Bytes())
		cKX, xKY := curve.ScalarMult(R.Ring[i].x, R.Ring[i].y, C.Bytes())
		ziX, ziY = curve.Add(rGX, rGY, cKX, xKY)

		rHpX, rHpY := curve.ScalarMult(hPX, hPY, rs.r[i].Bytes())
		cKDashX, xKDashY := curve.ScalarMult(rs.yDashX, rs.yDashY, C.Bytes())
		ziDashX, ziDashY = curve.Add(rHpX, rHpY, cKDashX, xKDashY)
		buffer.Write(R.Bytes())
		buffer.Write(rs.yDashX.Bytes())
		buffer.Write(rs.yDashY.Bytes())
		buffer.Write(m)
		buffer.Write(ziX.Bytes())
		buffer.Write(ziY.Bytes())
		buffer.Write(ziDashX.Bytes())
		buffer.Write(ziDashY.Bytes())
		C.SetBytes(hashN(buffer.Bytes()).Bytes())
		fmt.Printf("c[%d]=%d, ziDashX=%d; ziDashY=%d\n",i+1, C, ziDashX, ziDashY)
		buffer.Reset()
	}
//	fmt.Println(C)
//	fmt.Println(c0)
	return C.Cmp(rs.c0) == 0
}

//在签名有效且两个签名不属于同一人时，返回true，否则返回false
func linkable(rs1 RingSign, rs2 RingSign, R *PublicKeyRing, m []byte) bool{

	if verify(&rs1, R, m) && verify(&rs2, R, m){
		if rs1.yDashX != rs2.yDashX || rs1.yDashY != rs2.yDashY{
			return true
		}
	}
	return false
}

func main()  {
	rand.Seed(1)
	privKey := make([]Private,5) //存放私钥
	pubKey := make([]Public, 5) //存放公钥
	var curve = elliptic.P256()
	var err error
	for i := range privKey{
		privKey[i].D = new(big.Int)
		pubKey[i].y = new(big.Int)
		pubKey[i].x = new(big.Int)
		pubKey[i].Curve = curve
//		privKey[i].D, err = randFieldElement(curve, rand)
		privKey[i].D.SetInt64((int64(rand.Intn(173113)))) //随机产生私钥
		if err != nil {
			fmt.Println(err.Error())
		}
		pubKey[i].x, pubKey[i].y = curve.ScalarBaseMult(privKey[i].D.Bytes())

	}
	//公钥环
	pubkeyRing := &PublicKeyRing{
		pubKey,
	}
/*##############################使用环外成员##############################
	var testPriv Private
	testPriv.D = new(big.Int).SetInt64((int64(rand.Intn(173311))))
	spew.Dump(testPriv)
*/

	m := new(big.Int).SetInt64(193127)
	rs, err := sign(crand.Reader, pubkeyRing, m.Bytes(), privKey[1], 2)
	if verify(rs, pubkeyRing, m.Bytes()){
		fmt.Println("true")
	}else{
		fmt.Println("false")
	}
}
