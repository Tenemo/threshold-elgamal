/*
 The GROUPS object defines cryptographic parameters for different levels
 of finite field Diffie-Hellman (FFDHE) key exchanges.
 
 The parameters are standardized in RFC 7919 to ensure security,
 interoperability, and a balance between computational efficiency
 and resistance against cryptographic attacks.
 
 Each subgroup (ffdhe2048, ffdhe3072, ffdhe4096) corresponds to a security
 level, with larger primes offering stronger security but requiring more processing power.

 Reference: https://datatracker.ietf.org/doc/rfc7919/
 */
export const GROUPS = {
    // Parameters for 2048-bit prime modulus group
    ffdhe2048: {
        primeBits: 2048, // Size of the prime in bits, default security level suitable for current applications
        prime: 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039n,
        generator: 2n, // A small, primitive root modulo prime, used to generate public keys
        // Same as `prime` in this context, used for modulo operations in encryption/decryption
        modulus:
            16158503035655503650076756738912581681244028566744537587294217069634903417068105001396028181320082342729278178967665408464414511540286736312636777371230622870513101263958286486431353150162631714106572883465707111827110470555674314995828739134017115276543174525317778856109593945166364784848064871928120870618118612598673201345927898883988411507312698966529007613429365380598766218233737927730357521948422470183065248848906427147979329798783525641926066392234261462752284136439556860049465936979571687087918913000139017486599276030303766617061301627342044060015552953742140501997483478059848478124314516169036419563519n,
        symmetricEquivalentBitsSecurity: 103, // The estimated security level equivalent to symmetric key cryptography
    },
    // Parameters for 3072-bit prime modulus group
    ffdhe3072: {
        primeBits: 3072, // Provides higher security/complexity level
        prime: 5809605995369958062758586654274580047791722104970656507438869740087793294939022179753100900150316602414836960597893531254315756065700170507943025794723871619068282822579148207659984331724286057133800207014820356957933334364535176201393094406964280368146360322417397201921556656310696298417414318434929392806928868314831784332237038568260988712237196665742900353512788403877776568945491183287529096888884348887176901995757588549340219807606149955056871781046117195453427070254533858964729101754281121787330325506574928503501334937579191349178901801866451262831560570379780282604068262795024384318599710948857446185134652829941527736472860172354516733867877780829051346167153594329592339252295871976889069885964128038593002336846153522149026229984394781638501125312676451837144945451331832522946684620954184360294871798125320434686136230055213248587935623124338652624786221871129902570119964134282018641257113252046271726747647n,
        generator: 2n,
        modulus:
            2904802997684979031379293327137290023895861052485328253719434870043896647469511089876550450075158301207418480298946765627157878032850085253971512897361935809534141411289574103829992165862143028566900103507410178478966667182267588100696547203482140184073180161208698600960778328155348149208707159217464696403464434157415892166118519284130494356118598332871450176756394201938888284472745591643764548444442174443588450997878794274670109903803074977528435890523058597726713535127266929482364550877140560893665162753287464251750667468789595674589450900933225631415780285189890141302034131397512192159299855474428723092567326414970763868236430086177258366933938890414525673083576797164796169626147935988444534942982064019296501168423076761074513114992197390819250562656338225918572472725665916261473342310477092180147435899062660217343068115027606624293967811562169326312393110935564951285059982067141009320628556626023135863373823n,

        symmetricEquivalentBitsSecurity: 125,
    },
    // Parameters for 4096-bit prime modulus group
    ffdhe4096: {
        primeBits: 4096, // High security/complexity level
        prime: 1044388881413152506673611132423542708364181673367771525125030890756881099188024532056304793061869328458723091803972939229793654985168401497491717574483844225116618212565649899896238061528255690984013755361148305106047581812557457571303413897964307070369153233034916545609049161117676542252417034306148432734874401682098205055813065377495410934435776008569464677021023433005437163880753068613673525551966829473007537177831003494630326494021352410947409155250518131329542947165352164089215019548909074312164647627938366550236314760864116934087960021077839688388383033906117940935023026686459274599124189299486771919466921436930468113859003854695674493896608503326776616230412252016237753188005160515672431703429026925450722225213972891936880551722374424500117253400391608019951133386097176734162660461073160502839490488652900367939577292447038637156268014222959401811270825513710710113193757653852931049810187522670964988718456427706279024201400130351029277257873323362974483425793829163819060563081096261611614988801585554385004830748976181157545121697905898543562330970182151097394600286811868072516047394404389555706298311761588649133904051123770516767707951778179308436153604841663369568605395358405635911568855382987714763476172799n,
        generator: 2n,
        modulus:
            522194440706576253336805566211771354182090836683885762562515445378440549594012266028152396530934664229361545901986469614896827492584200748745858787241922112558309106282824949948119030764127845492006877680574152553023790906278728785651706948982153535184576616517458272804524580558838271126208517153074216367437200841049102527906532688747705467217888004284732338510511716502718581940376534306836762775983414736503768588915501747315163247010676205473704577625259065664771473582676082044607509774454537156082323813969183275118157380432058467043980010538919844194191516953058970467511513343229637299562094649743385959733460718465234056929501927347837246948304251663388308115206126008118876594002580257836215851714513462725361112606986445968440275861187212250058626700195804009975566693048588367081330230536580251419745244326450183969788646223519318578134007111479700905635412756855355056596878826926465524905093761335482494359228213853139512100700065175514638628936661681487241712896914581909530281540548130805807494400792777192502415374488090578772560848952949271781165485091075548697300143405934036258023697202194777853149155880794324566952025561885258383853975889089654218076802420831684784302697679202817955784427691493857381738086399n,
        symmetricEquivalentBitsSecurity: 150,
    },
} as const;
