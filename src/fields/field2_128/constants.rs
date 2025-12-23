//! Precomputed constants used in various operations in GF(2^128). These are over here because
//! because it would be annoying to scroll past them while reading other modules.

use crate::fields::field2_128::{Field2_128, SubfieldBasisLowerUpperDecomposition};

/// The basis of the subfield GF(2^16), viewed as a vector space over GF(2), used to inject integers
/// into [`Field2_128`] so that they can be efficiently stored in proofs.
///
/// The generator is g=x^{(2^{128}-1) / (2^{16}-1)} and the basis consists of g^i for 0 <= i <
/// 16. Despite the actual field having 128 bits, this 16 bit basis is large enough for values
/// in the Longfellow commitment scheme.
///
/// Described in section 3.3 of [Longfellow][1], and in [section 2.2.2][2] of the specification.
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf
/// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
pub(crate) const fn subfield_basis() -> [Field2_128; Field2_128::SUBFIELD_BIT_LENGTH] {
    // Computed in SageMath:
    // GF2 = GF(2)
    // x = polygen(GF2)
    // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
    // # (2^128 - 1) / (2^16 - 1) = 5192376087906286159508272029171713
    // g = GF2_128(x)^5192376087906286159508272029171713
    // for i in range(16):
    //     print((g^i).to_integer())
    [
        Field2_128::from_u128_const(1),
        Field2_128::from_u128_const(122753392676920971658749122761936853580),
        Field2_128::from_u128_const(185726315739164108859399796142663757480),
        Field2_128::from_u128_const(242075443675499227109267320400911498989),
        Field2_128::from_u128_const(222542784214874944227167260511584909351),
        Field2_128::from_u128_const(112425233274138136655968706803108112542),
        Field2_128::from_u128_const(111955919296675432803292387102199683976),
        Field2_128::from_u128_const(98263563783606923211003062286538201250),
        Field2_128::from_u128_const(201564998845547644025367330818532893392),
        Field2_128::from_u128_const(160337305018218142404182087593505552404),
        Field2_128::from_u128_const(226322062164902409880343938983895220315),
        Field2_128::from_u128_const(162097237762330204766181745825071946233),
        Field2_128::from_u128_const(231881152083561309652087018093156258488),
        Field2_128::from_u128_const(285712114744156533702206238221900352048),
        Field2_128::from_u128_const(7298129229485713500594372746195714592),
        Field2_128::from_u128_const(33006046103584326006971076539670943571),
    ]
}

/// The precomputed lower-upper decomposition of the basis of the [`Field2_128`] subfield
/// ([`subfield_basis`]). Used to attempt projection of GF(2^128) elements into the subfield, as
/// described in [FS24 section 3.3][1].
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf#subsection.3.3
pub(crate) const fn subfield_basis_lu_decomposition() -> SubfieldBasisLowerUpperDecomposition {
    // Computed using fields::field2_128::constants::test::compute_subfield_basis_lu_decomposition.
    // We can't evaluate that function in const because its loops call methods on trait `Iterator`
    // and related types.
    SubfieldBasisLowerUpperDecomposition {
        upper: [
            0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001,
            0b10100111011011000010111001100011010011000110010010000011101011101001101110100011001010000010000010000111101000111111100000100110,
            0b10110110000111100000100011011010000100101111100101100110010111000011111110001101111010001010001011111001111111110111111011101100,
            0b10001011101110011001011001011000111010101111001011001010111000001010011011100011000100001111101101101110000101110110111010101000,
            0b01111000010000011111011111001111000000111011000011010101101000111100101011101111011101100100100010001011001010111111111000010000,
            0b11101010010001110111100101011101011001111111100010110010111001001100111000001010111101101010001101001111101100001010010010100000,
            0b11010011001001110110111101011111101100100001100001010100000100001110011110101011001010011000010100101101110100001011000011000000,
            0b00110101110001110000001111111000111110001010001100101000110111001011100010011111101110010100000001010010100101110101000110000000,
            0b11011011100110011101001010010011100011011110011101010111111010110110110001010001110001010000100010001010111100110111011100000000,
            0b00101101001010010000101100110000011000110011110100101101001100000111101011111110100111011001101001010111110010001001111000000000,
            0b00111100110000101001100100100111100000100100111011101011001000000011010011101011011111111001100100110001000000111010110000000000,
            0b01101100111010101100011111101011110100110100111101110010110100100001000100010111110101100000101110010111111100011010100000000000,
            0b01001100011000010101110011111000100111001111111111011010001011101101010011001000011111001111111100110101100110111111000000000000,
            0b11101011011010011011010111110101001000101010101000010011010010011111000100111011111110011100001010001010000101001100000000000000,
            0b11010010111111100011000111111100010001001110110001101010111101000000100000111011110001000101111011001111110111111000000000000000,
            0b11101010000011011000110001001110011110010101111111111011011001101110010011001000110100111000110111000100110110110000000000000000,
        ],
        lower_inverse: [
            0b0000000000000000000000000000000000000000000000000000000000000001,
            0b0000000000000000000000000000000000000000000000000000000000010001,
            0b0000000000000000000000000000000000000000000000000000000000001001,
            0b0000000000000000000000000000000000000000000000000000000000000100,
            0b0000000000000000000000000000000000000000000000000000000000110101,
            0b0000000000000000000000000000000000000000000000000000000000001011,
            0b0000000000000000000000000000000000000000000000000000000010011100,
            0b0000000000000000000000000000000000000000000000000000000001001111,
            0b0000000000000000000000000000000000000000000000000000001011101011,
            0b0000000000000000000000000000000000000000000000000000011010001000,
            0b0000000000000000000000000000000000000000000000000000000110101001,
            0b0000000000000000000000000000000000000000000000000000100011100011,
            0b0000000000000000000000000000000000000000000000000001011100010000,
            0b0000000000000000000000000000000000000000000000000010110011110001,
            0b0000000000000000000000000000000000000000000000001011001011000111,
            0b0000000000000000000000000000000000000000000000000110111001011110,
        ],
        first_nonzero: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16],
    }
}

/// The precomputed array used in the twiddle function for additive Fast Fourier Transforms in
/// [`Field2_128`]. Also "W^hat" in [FS24 section 3.2][1], or the normalized subspace vanishing
/// polynomials.
///
/// Element [i][j] of this array represents W^hat_i(beta_j).
///
/// [1]: https://eprint.iacr.org/2024/2010.pdf#subsection.3.2
pub(crate) const fn twiddle_array()
-> [[Field2_128; Field2_128::SUBFIELD_BIT_LENGTH]; Field2_128::SUBFIELD_BIT_LENGTH] {
    // Computed using fields::field2_128::constants::test::compute_twiddle_array. We can't evaluate
    // that function in const because its loops call methods on trait `Iterator` and related types.
    [
        [
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(122753392676920971658749122761936853580),
            Field2_128::from_u128_const(185726315739164108859399796142663757480),
            Field2_128::from_u128_const(242075443675499227109267320400911498989),
            Field2_128::from_u128_const(222542784214874944227167260511584909351),
            Field2_128::from_u128_const(112425233274138136655968706803108112542),
            Field2_128::from_u128_const(111955919296675432803292387102199683976),
            Field2_128::from_u128_const(98263563783606923211003062286538201250),
            Field2_128::from_u128_const(201564998845547644025367330818532893392),
            Field2_128::from_u128_const(160337305018218142404182087593505552404),
            Field2_128::from_u128_const(226322062164902409880343938983895220315),
            Field2_128::from_u128_const(162097237762330204766181745825071946233),
            Field2_128::from_u128_const(231881152083561309652087018093156258488),
            Field2_128::from_u128_const(285712114744156533702206238221900352048),
            Field2_128::from_u128_const(7298129229485713500594372746195714592),
            Field2_128::from_u128_const(33006046103584326006971076539670943571),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(286951796544069427116289924355363222756),
            Field2_128::from_u128_const(205758735199428137656536022487254427746),
            Field2_128::from_u128_const(23757469676399553940038052538735621596),
            Field2_128::from_u128_const(161549623495630183708663389875042496835),
            Field2_128::from_u128_const(16275930523155067441630209938366198059),
            Field2_128::from_u128_const(190300499423516401406868752291218395892),
            Field2_128::from_u128_const(11448054044492245544708082350784790892),
            Field2_128::from_u128_const(28148182364517770471961017904963996257),
            Field2_128::from_u128_const(154977613376610097022172464622995110854),
            Field2_128::from_u128_const(76510322097641330670743902342087859838),
            Field2_128::from_u128_const(238362568792294389666080992445392941271),
            Field2_128::from_u128_const(173217726505858477928634410586126651478),
            Field2_128::from_u128_const(81545844897013238588158283858154956233),
            Field2_128::from_u128_const(189175746861513884278977899876925272681),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(149604548812814971135929617817875991747),
            Field2_128::from_u128_const(18287642172741067191237245240449235364),
            Field2_128::from_u128_const(307091996710368962282810895442127142609),
            Field2_128::from_u128_const(201835466705828260825510313465461159048),
            Field2_128::from_u128_const(194258834002682884674953542971235556380),
            Field2_128::from_u128_const(248981368054472319760436396505833520019),
            Field2_128::from_u128_const(178136518006013047973130452485618317015),
            Field2_128::from_u128_const(313676359486875526854146978029369761794),
            Field2_128::from_u128_const(92353577814579651570056745768523583833),
            Field2_128::from_u128_const(195670921082380475412214841834596521965),
            Field2_128::from_u128_const(134351024333749293707731262765274912041),
            Field2_128::from_u128_const(74870318249022658301033765250020402553),
            Field2_128::from_u128_const(32567027570433742491675553581848801066),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(307263416323549896857530870633261674003),
            Field2_128::from_u128_const(82261261761985330095318507405292410799),
            Field2_128::from_u128_const(338608655987419545865071306860662489358),
            Field2_128::from_u128_const(302330271307028456681319155803179903359),
            Field2_128::from_u128_const(195892472845583133581572054558965677184),
            Field2_128::from_u128_const(236934410982817785485347228471245885754),
            Field2_128::from_u128_const(312356217329746682073303095870834666114),
            Field2_128::from_u128_const(269194236549396743112079843039137721637),
            Field2_128::from_u128_const(22576919569049008877775826437195400979),
            Field2_128::from_u128_const(113634793632070596656432600399929337856),
            Field2_128::from_u128_const(117803143902495298852781605950600491320),
            Field2_128::from_u128_const(190038277193786052885877982693364496125),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(228135735640806269028499007403483376367),
            Field2_128::from_u128_const(274212946793736732184887430496366720169),
            Field2_128::from_u128_const(178264668457174907519505051147403859531),
            Field2_128::from_u128_const(306080296125733219811682242544493294523),
            Field2_128::from_u128_const(327773836761295472749990895064997074991),
            Field2_128::from_u128_const(198128310469225103564532344069124399),
            Field2_128::from_u128_const(65176661250063127310677367247900067852),
            Field2_128::from_u128_const(242342804780088945017155417130892677514),
            Field2_128::from_u128_const(138772011260490117816252961574289306816),
            Field2_128::from_u128_const(205253056393609005522875972501154885983),
            Field2_128::from_u128_const(317726287660162658821387861477302583473),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(217250839138421353436318368084321759680),
            Field2_128::from_u128_const(317754180356169049724161533948814551100),
            Field2_128::from_u128_const(16927176668965923175402717746039624447),
            Field2_128::from_u128_const(258776387831806339857021365896849098817),
            Field2_128::from_u128_const(17666080074338456966664106913120137980),
            Field2_128::from_u128_const(60009081516200663335631386860132791339),
            Field2_128::from_u128_const(102991965940264533127899026339393950588),
            Field2_128::from_u128_const(112331229927218020056263576011034372590),
            Field2_128::from_u128_const(184500073728661779510508730900433841535),
            Field2_128::from_u128_const(211218446533310416807092936054851981786),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(173925311393179455246569828224129260302),
            Field2_128::from_u128_const(296308313587701766766948086293600070191),
            Field2_128::from_u128_const(33332068644302616674122975055691889483),
            Field2_128::from_u128_const(155900095362269519779319759163748677093),
            Field2_128::from_u128_const(43587746736855930083301997797325514856),
            Field2_128::from_u128_const(296423362206237654114472540790749486996),
            Field2_128::from_u128_const(114177498896775655524413766364624920718),
            Field2_128::from_u128_const(55022947539972640258572133274184718364),
            Field2_128::from_u128_const(113051992297966524881852629333968671858),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(297062813223354907329411156269979989384),
            Field2_128::from_u128_const(55498875102507815491353012386755245730),
            Field2_128::from_u128_const(97183195234143136341179557816284787233),
            Field2_128::from_u128_const(270403797531338209745567427038712884667),
            Field2_128::from_u128_const(123713051752486943980447104415706581647),
            Field2_128::from_u128_const(133020482301726714061969471043085869386),
            Field2_128::from_u128_const(129084436268751443109719694773436356216),
            Field2_128::from_u128_const(300999069130577813329649794063126094168),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(1645703777016437714629157206641955411),
            Field2_128::from_u128_const(231496577504192395792668042882768762319),
            Field2_128::from_u128_const(317726287660162658821387861477302583473),
            Field2_128::from_u128_const(27694789911334405391595093561069647213),
            Field2_128::from_u128_const(22687114254299160926038189888566784014),
            Field2_128::from_u128_const(58546241224996357010262736068369977482),
            Field2_128::from_u128_const(264487024855738888491702452631261417506),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(38037535346261701501342686448200276617),
            Field2_128::from_u128_const(54221509729363911693681432243308123656),
            Field2_128::from_u128_const(301991129608627453072761912641719839795),
            Field2_128::from_u128_const(70357236220939224698835302321949477827),
            Field2_128::from_u128_const(339250576658533255637023616542837909595),
            Field2_128::from_u128_const(47859474030351277790005742802004690535),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(217480865654509432899360809558247575290),
            Field2_128::from_u128_const(189903756104397162778830291913051146195),
            Field2_128::from_u128_const(222867999970256714018398050712535064668),
            Field2_128::from_u128_const(139517438828506211642716080863358198247),
            Field2_128::from_u128_const(285320343925353838224981329933203993161),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(258795108754019427095027841722093167037),
            Field2_128::from_u128_const(98205778530760675500084609155277246157),
            Field2_128::from_u128_const(205350314264990556018588615100340325482),
            Field2_128::from_u128_const(91685833721197891782118719076912795535),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(337885671867720762115972294340238537909),
            Field2_128::from_u128_const(133312971165295752178238705787144490844),
            Field2_128::from_u128_const(79865913147303941867309655175065324520),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(34075701874363500988951311760257950112),
            Field2_128::from_u128_const(60671999173760487464442662968386560731),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
            Field2_128::from_u128_const(333868580667653917453718037019227144272),
        ],
        [
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(0),
            Field2_128::from_u128_const(1),
        ],
    ]
}

/// Access element [x][y] of `twiddle_array()`
pub(crate) fn twiddle_array_at(x: u32, y: u32) -> Field2_128 {
    // unwrap safety: u32 will fit into a usize anywhere we are deploying
    twiddle_array()[usize::try_from(x).expect("u32 too big for usize?")]
        [usize::try_from(y).expect("u32 too big for usize?")]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::{CodecFieldElement, FieldElement, field2_128::Field2_128};

    /// Compute the twiddle array W^hat from the subfield basis and the subspace vanishing
    /// polynomials. See [`twiddle_array`] for more discussion.
    fn compute_twiddle_array()
    -> [[Field2_128; Field2_128::SUBFIELD_BIT_LENGTH]; Field2_128::SUBFIELD_BIT_LENGTH] {
        let mut twiddles = [[Field2_128::ZERO; _]; _];

        // base case: W_0(x) = x so we fill row 0 with the basis
        twiddles[0] = subfield_basis();

        // inductive case: W_i(x) = W_i-1(x)*(W_i-1(x)+W_i-1(beta_i-1))
        for i in 1..twiddles.len() {
            for j in 0..twiddles[i].len() {
                twiddles[i][j] = twiddles[i - 1][j] * (twiddles[i - 1][j] + twiddles[i - 1][i - 1]);
            }
        }

        // Normalize into W^hat by dividing each element W[i][j] by W_i(beta_i) = W[i][i]
        for (i, row) in twiddles.iter_mut().enumerate().skip(1) {
            let beta_inv = row[i].mul_inv();
            for twiddle in row.iter_mut() {
                *twiddle *= beta_inv;
            }
        }

        twiddles
    }

    #[test]
    fn twiddle_array_equivalence() {
        // Print out the computed twiddle array as a literal so it can be copy-pasted into function
        // twiddle_array
        println!("[");
        for row in compute_twiddle_array() {
            println!("[");
            for element in row {
                println!("Self::from_u128_const({}),", element.0);
            }
            println!("],")
        }
        print!("]");

        assert_eq!(twiddle_array(), compute_twiddle_array());
    }

    fn compute_subfield_basis_lu_decomposition() -> SubfieldBasisLowerUpperDecomposition {
        // Make sure our definition of the subfield basis is consistent with everything else.
        assert_eq!(Field2_128::SUBFIELD_BIT_LENGTH, subfield_basis().len());

        // Construct the matrix B whose rows are the elements of the subfield basis vector
        // interpreted as vectors of 128 bits.
        let mut upper = [0u128; Field2_128::SUBFIELD_BIT_LENGTH];
        for (upper_element, subfield_basis_element) in upper.iter_mut().zip(subfield_basis()) {
            *upper_element = subfield_basis_element.0;
        }

        // Negative of identity matrix (-I). Negation in GF(2) is a no-op.
        let mut lower_inverse = [0u16; Field2_128::SUBFIELD_BIT_LENGTH];
        for (index, li_element) in lower_inverse.iter_mut().enumerate() {
            *li_element = 1 << index;
        }

        // first_nonzero[i] is the index of the first column in row i that is not zero.
        let mut first_nonzero = [0usize; Field2_128::SUBFIELD_BIT_LENGTH];

        // Reduce B to row echelon form, thus converting -I to -L^(-1)
        let mut rank = 0usize;
        for j in 0..Field2_128::NUM_BITS {
            // find pivot at row >= rank in column j
            let mut found_pivot = false;
            for i in rank..Field2_128::SUBFIELD_BIT_LENGTH {
                if (upper[i] >> j) & 1 == 1 {
                    upper.swap(i, rank);
                    lower_inverse.swap(i, rank);

                    found_pivot = true;
                    break;
                }
            }

            if !found_pivot {
                // No pivot for this rank on this row. We'll keep looking in the next row.
                continue;
            }

            first_nonzero[rank] = j.try_into().expect("u32 too big for usize?");

            // Pivot on [rank][j]
            for i in (rank + 1)..Field2_128::SUBFIELD_BIT_LENGTH {
                if (upper[i] >> j) & 1 == 1 {
                    upper[i] ^= upper[rank];
                    lower_inverse[i] ^= lower_inverse[rank];
                }
            }
            rank += 1;
            if rank == Field2_128::SUBFIELD_BIT_LENGTH {
                break;
            }
        }

        assert_eq!(rank, Field2_128::SUBFIELD_BIT_LENGTH);

        SubfieldBasisLowerUpperDecomposition {
            upper,
            lower_inverse,
            first_nonzero,
        }
    }

    #[test]
    fn subfield_basis_lu_decomposition_equivalence() {
        let decomposition = compute_subfield_basis_lu_decomposition();
        // Print out the LU decomposition as a literal so it can be copy-pasted into function
        // subfield_basis_lu_decomposition
        println!(
            r#"SubfieldBasisLowerUpperDecomposition {{
  upper: ["#
        );
        for upper_elem in decomposition.upper {
            println!("    0b{:0128b},", upper_elem);
        }
        println!(
            r#"  ],
  lower_inverse: ["#
        );
        for lower_elem in decomposition.lower_inverse {
            println!("    0b{:064b},", lower_elem);
        }
        println!(
            r#"  ],
  first_nonzero: ["#
        );
        for element in decomposition.first_nonzero {
            println!("    {},", element);
        }
        println!(
            r#"  ],
}}"#
        );

        assert_eq!(decomposition, subfield_basis_lu_decomposition());
    }
}
