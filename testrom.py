import base64
from edlinkn8 import Everdrive, NesRom, BPSPatch

# Test rom from: https://github.com/zohassadar/NESHelloWorld/tree/v0.1

TEST_ROM_LEN = 40976

FIFO_TESTROM = (
    b"LQqpN5I=zsKY@UmPDN810s#Y}fGvR9fYyKlf$x9=ff9jEfmVTDfdB#pqzR=87<m$a3aY&TfQ10P0f2=8"
    b"Yybd{$_;_gOr-@W0`LjO3lIgl$AE<kr3EPg@D1h*r3=~0fY1b~0EG*s3-BhT3mAFLfU2bhDG2Zg_7}Am"
    b"DG!wwr3EPj@CeqM8i0vRpn#K|r3uCg5Cyr=fQ1T^l9>(W3Z)9!)0fM+3LuYxr3EQ~@CG0ifK0rP)J1?m"
    b"@CT&{@B<*;fT;k52c-w_{7fu>00;&F2?qcG2mt~E0s{o80?-Dj0nh@e0EG$W43Fb|fQ1UF1BD1+r4aBB"
    b"pa7*0kqzb#$ixuP_2vv<pa8KAnI-_pz!1>(<_ut^6wm~v74S3W45=%P@IXobjqpIJBA*n3g{2gaj)4`A"
    b"iRBZd6{ZyM295AQ%Fz0V!2i(oVCD?1@j!(UkGPTWK!p-ulV5<L7KInB@j%Hz(2rn%VS?rs(DLRNOlE;#"
    b"7#bWNA|xOg8yz1bB_R$C4-gd;6QBUTdV#e73JMAezJY-i0KSNUl>o@V2hiwXNQy|9Nag~m0fh&p2q4{o"
    b"sQ`@yAdLkesfdjLAgK<G0U#jaglMQ}s%Sv&fjWXWgARnH2nwpb)q#Zoz1D$~X@k|NAdLnfsiBPqAfj)e"
    b"gdjPDsUeL9Ad@DBg`$6#m4PCop@Ec>g1My(AWDR$3cXo`jRqjSU60n4sql>lAYhjPfPsULf}sql|BVMA"
    b"$`Jaimz%_u7>x%Yr5TU@ff|p3i5ravqo;u!kCuTQtAc?ZkAjIGjR%)|fR~Gbm#d+Z9)N+Ks~v!oqm=-)"
    b"CLl_LllYP7;0Vz1m-m4|mr#L$F3W<y1%i#G3(ynGfQ_XK@EDVVy`~GjV1yWHf*55BjRqj8@u!o4h>sV5"
    b"fe*_XfPti!+JPXCf`K8Ap@FQIB!Yn=kAi_CkD7rbkAi_Ew@re9wU-Tmff0{NfTzWQ!<R3BffA2OfTyE@"
    b"(U(zxl@}mNgrydv6oiwlf#35Dg|9+_k!XY%X@|3lxd4p-AdLYar3r-yqQIa8mwkeb0F4G9mj;6+g3$Vi"
    b"(Dy6?AQ1ath5&>Cpa8J|@CJ<sAjr`6U`R?zN=l6fAZRHMjRzoLAR!?lp&_9m000000s;gC000OG2nZlj"
    b"K}{f1WnpA5S8{1|WdI;Wc4cy8a%pyDAVx_>Pasrfb94Y8Bmf|rV1tjDl>i`9Wo~4TxRGOTb#8QziI2&d"
    b"AS5&}W-&dl_JJ^uf~9O_ZYXheWp!mKkBM!8Bmk)ajTS(K1xk$;K&=))N+t!6_@xC%MFu4Wg#~DZ24HyD"
    b"qCk!pK%)Pe=#Bs&jsYN!5I`&fARse@ij@GJ00Er<0-XQ@od5)#00o@@2Au#0=+NdMGlZ!>pGkp{q5!>N"
    b"g_8$_l_1ddAR2_1QG=--jR7D`EPxL%Ffi{jjbc)UleMaW0)^Cp9y2#TJ2M^tp9X1yl?)sV3=9mXjF}!Y"
    b"2M!!KKdX+30}ca|%a_oZ1`ZY`KL!S)j*UMsJ_C=bpRkc0GcZ0gtBRRFBLfBo3=E@=i5@dEkC3m6fghLO"
    b"qu`A{Gcz-zh?#yfGd?pjexr_=A2Ts9FfksZj*Fp-u9Lr$u$g}`Fg!3Zf47c>FmR)UKZhNMnHU%t7#IK;"
    b"qbi4qY-~uAM~9zGhlwbBe2<W$i<uBSa5x-z5TlNn#?Bl#aOTFNj+r=Qa5`*eI-`z>7#I+nJAj)&fPpZN"
    b"kc(e{pHP60Z-{{mr*Mds0Bkt^IBbt+fSYoFkr)_$7#ORHlL>%<2(Jo&fjpZrik~uykF%q)nG6gZ7&tI6"
    b"qmG$8W^R6VW;~;gl^8e}7#J9*jF~)U4jedeeyfg&1{?;H%a_oZ3>+*>ehdtwj*Wg`d<KuHpRkcUW?+0~"
    b"tBRR^Mg|NF7#O3Di9BXzkC3m6fj*btm*9_Cft&fOP=bL7qk@?X7%*Tk7!0G1k8gsPg_m-Ii>ZwU3>Yw@"
    b"u$4S!1`HSgk5z!5V1SKoZeU`QX@Z+@f{|u^W@cuiikbXoW_)I5{G*PIK4xNIkIA3Vi=m6IlfRR&nf_v6"
    b"cwl1ww~mEi;G=|@e8#}e#>RZ3j*IJ)*PlRufjpC8h=Dw#WQdtQ3=9kmOgN*Cnf7LEcx-0&qmG$)FfcGM"
    b"GJd0una1w^*2c!hqmGegW_EsVlP7?eFo1zPlTU$@@smJ;k0FAIU|{g0CW4cpg={*bq?ciWf##!Pf|)*I"
    b"U_1s!e4~zqep;73fuBHulMjP|X15T7iEca?qlTHr#>UqEY(%4uk!EH*7(A0_f}e1Li@kvukCT_snSM?j"
    b"IB;TqqmF?*lTV9*Jfl*JnJ_Ro7#s`?qmF?*lW&WGJfm`pfe@2fi-7>6T#J`!mVthwYL=NWI2;TB005(o"
    b"nE(Jh20ms!qmG$iV0>m~W_+WLi=mBTU}8L@sF?-^K4xZSKBJC{p^0XGV3UiJu$2xN7(5slr;MEd06u1B"
    b"J_bCWkey&)Y<6a5W&od%i5LJlmurlhaEyfv0F!^1fjFN8nU!E*WNdhBkHweJlTVF>7(Am=jhO%d?AF%S"
    b")~k+%TxO3QfTtjUk9CHZM1+?xfq{IJV}_?>hLbUYfd;2Cfr)H(V2_!jo{c<UJO-0#f|GE9nJ_SXFfcG2"
    b"qmF?9lXHfFI=6O)g*+Imgpo#8R#rZ%ij#AOuX2WoW<Ca&`<DQKk$f09FnptmjT|sAV2??FpHP64UxKS_"
    b"f}J=F3<eAgH~^o5kpKWPeoT`Ela~&YojgLBp{1EZJfDyQw|}~sKwxlqa9}{A47-g0e?A<Ocdws*uXlre"
    b"y@CI`48H%bzfXdH{sX&52Es?=L)0lqfPZ="
)


def count_bytes(everdrive: Everdrive):
    counter = 0
    while True:
        byte_ = everdrive.receive_data(1)
        if not byte_:
            break
        counter += 1
    print(counter)


def send_fifo(everdrive: Everdrive, *numbers):
    payload = bytearray(n & 0xFF for n in numbers)
    everdrive.write_fifo(payload)


def get_test_rom() -> bytearray:
    rom = bytearray(TEST_ROM_LEN)
    patch = base64.b85decode(FIFO_TESTROM)
    bps_patch = BPSPatch(patch)
    return bps_patch.patch_rom(rom)


if __name__ == "__main__":
    everdrive = Everdrive()
    testrom = NesRom(rom=get_test_rom(), name="testrom.nes")
    everdrive.load_game(testrom)
