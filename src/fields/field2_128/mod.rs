//! Implementation of GF(2^128).
//!
//! This is defined using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.

use crate::{
    Codec,
    fields::{CodecFieldElement, FieldElement, LagrangePolynomialFieldElement, addition_chains},
};
use anyhow::Context;
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicU8, Ordering};
use std::{
    cmp::min,
    fmt::Debug,
    io::{Cursor, Read},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use subtle::ConstantTimeEq;

/// An element of the field GF(2^128).
///
/// This field is constructed using the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
#[derive(Clone, Copy)]
pub struct Field2_128(u128);

impl Field2_128 {
    const SUBFIELD_BIT_LENGTH: usize = 16;

    /// Project a u128 integer into a field element.
    ///
    /// This duplicates `FieldElement::from_u128()` in order to provide a const function with the
    /// same functionality, since trait methods cannot be used in const contexts yet.
    const fn from_u128_const(value: u128) -> Self {
        Self(value)
    }

    /// The novel polynomial basis used to inject integers into this field so that they can be
    /// efficiently multiplied with other field elements.
    ///
    /// The generator is g=x^{(2^{128}-1) / (2^{16}-1)} and the basis consists of g^i for 0 <= i <
    /// 16. Despite the actual field having 128 bits, this 16 bit basis is large enough for values
    /// in the Longfellow commitment scheme.
    ///
    /// Described in section 3.3 of [Longfellow][1], and in [section 2.2.2][2] of the specification.
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    /// [2]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
    // Restrict this to test cfg for now, to avoid a dead_code warning
    #[cfg(test)]
    const fn subfield_basis() -> [Self; Self::SUBFIELD_BIT_LENGTH] {
        // Computed in SageMath:
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // # (2^128 - 1) / (2^16 - 1) = 5192376087906286159508272029171713
        // g = GF2_128(x)^5192376087906286159508272029171713
        // for i in range(16):
        //     print((g^i).to_integer())
        [
            Self::from_u128_const(1),
            Self::from_u128_const(122753392676920971658749122761936853580),
            Self::from_u128_const(185726315739164108859399796142663757480),
            Self::from_u128_const(242075443675499227109267320400911498989),
            Self::from_u128_const(222542784214874944227167260511584909351),
            Self::from_u128_const(112425233274138136655968706803108112542),
            Self::from_u128_const(111955919296675432803292387102199683976),
            Self::from_u128_const(98263563783606923211003062286538201250),
            Self::from_u128_const(201564998845547644025367330818532893392),
            Self::from_u128_const(160337305018218142404182087593505552404),
            Self::from_u128_const(226322062164902409880343938983895220315),
            Self::from_u128_const(162097237762330204766181745825071946233),
            Self::from_u128_const(231881152083561309652087018093156258488),
            Self::from_u128_const(285712114744156533702206238221900352048),
            Self::from_u128_const(7298129229485713500594372746195714592),
            Self::from_u128_const(33006046103584326006971076539670943571),
        ]
    }

    /// Inject the value into the field using the subfield basis, per [2.2.2][1]. The basis only has
    /// 16 elements, so we can't inject anything bigger than u16.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-2.2.2
    // Restrict this to test cfg for now, to avoid a dead_code warning
    #[cfg(test)]
    fn inject(mut value: u16) -> Self {
        let mut injected = Self::ZERO;
        for basis_element in Self::subfield_basis() {
            if value & 1 == 1 {
                injected += basis_element;
            }
            value >>= 1;
        }

        injected
    }

    /// Compute the twiddle array W^hat from the novel polynomial basis. See [`Self::twiddle_array`]
    /// for more discussion.
    #[cfg(test)]
    fn compute_twiddle_array() -> [[Self; Self::SUBFIELD_BIT_LENGTH]; Self::SUBFIELD_BIT_LENGTH] {
        let mut twiddles = [[Self::ZERO; Self::SUBFIELD_BIT_LENGTH]; Self::SUBFIELD_BIT_LENGTH];

        // base case: W_0(x) = x so we fill row 0 with the basis
        twiddles[0] = Self::subfield_basis();

        // inductive case: W_i(x) = W_i-1(x)*(W_i-1(x)+W_i-1(beta_i-1))
        for i in 1..Self::SUBFIELD_BIT_LENGTH {
            for j in 0..Self::SUBFIELD_BIT_LENGTH {
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

    /// The precomputed array used in the twiddle function for Fast Fourier Transforms. Also "W^hat"
    /// in section 3.2 of the [paper][1], or the normalized subspace vanishing polynomials.
    ///
    /// Element [i][j] of this array represents W^hat_i(beta_j).
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    const fn twiddle_array() -> [[Self; Self::SUBFIELD_BIT_LENGTH]; Self::SUBFIELD_BIT_LENGTH] {
        // Computed using Self::compute_twiddle_array. We can't evaluate that function in const
        // because it uses loops.
        [
            [
                Self::from_u128_const(1),
                Self::from_u128_const(122753392676920971658749122761936853580),
                Self::from_u128_const(185726315739164108859399796142663757480),
                Self::from_u128_const(242075443675499227109267320400911498989),
                Self::from_u128_const(222542784214874944227167260511584909351),
                Self::from_u128_const(112425233274138136655968706803108112542),
                Self::from_u128_const(111955919296675432803292387102199683976),
                Self::from_u128_const(98263563783606923211003062286538201250),
                Self::from_u128_const(201564998845547644025367330818532893392),
                Self::from_u128_const(160337305018218142404182087593505552404),
                Self::from_u128_const(226322062164902409880343938983895220315),
                Self::from_u128_const(162097237762330204766181745825071946233),
                Self::from_u128_const(231881152083561309652087018093156258488),
                Self::from_u128_const(285712114744156533702206238221900352048),
                Self::from_u128_const(7298129229485713500594372746195714592),
                Self::from_u128_const(33006046103584326006971076539670943571),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(286951796544069427116289924355363222756),
                Self::from_u128_const(205758735199428137656536022487254427746),
                Self::from_u128_const(23757469676399553940038052538735621596),
                Self::from_u128_const(161549623495630183708663389875042496835),
                Self::from_u128_const(16275930523155067441630209938366198059),
                Self::from_u128_const(190300499423516401406868752291218395892),
                Self::from_u128_const(11448054044492245544708082350784790892),
                Self::from_u128_const(28148182364517770471961017904963996257),
                Self::from_u128_const(154977613376610097022172464622995110854),
                Self::from_u128_const(76510322097641330670743902342087859838),
                Self::from_u128_const(238362568792294389666080992445392941271),
                Self::from_u128_const(173217726505858477928634410586126651478),
                Self::from_u128_const(81545844897013238588158283858154956233),
                Self::from_u128_const(189175746861513884278977899876925272681),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(149604548812814971135929617817875991747),
                Self::from_u128_const(18287642172741067191237245240449235364),
                Self::from_u128_const(307091996710368962282810895442127142609),
                Self::from_u128_const(201835466705828260825510313465461159048),
                Self::from_u128_const(194258834002682884674953542971235556380),
                Self::from_u128_const(248981368054472319760436396505833520019),
                Self::from_u128_const(178136518006013047973130452485618317015),
                Self::from_u128_const(313676359486875526854146978029369761794),
                Self::from_u128_const(92353577814579651570056745768523583833),
                Self::from_u128_const(195670921082380475412214841834596521965),
                Self::from_u128_const(134351024333749293707731262765274912041),
                Self::from_u128_const(74870318249022658301033765250020402553),
                Self::from_u128_const(32567027570433742491675553581848801066),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(307263416323549896857530870633261674003),
                Self::from_u128_const(82261261761985330095318507405292410799),
                Self::from_u128_const(338608655987419545865071306860662489358),
                Self::from_u128_const(302330271307028456681319155803179903359),
                Self::from_u128_const(195892472845583133581572054558965677184),
                Self::from_u128_const(236934410982817785485347228471245885754),
                Self::from_u128_const(312356217329746682073303095870834666114),
                Self::from_u128_const(269194236549396743112079843039137721637),
                Self::from_u128_const(22576919569049008877775826437195400979),
                Self::from_u128_const(113634793632070596656432600399929337856),
                Self::from_u128_const(117803143902495298852781605950600491320),
                Self::from_u128_const(190038277193786052885877982693364496125),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(228135735640806269028499007403483376367),
                Self::from_u128_const(274212946793736732184887430496366720169),
                Self::from_u128_const(178264668457174907519505051147403859531),
                Self::from_u128_const(306080296125733219811682242544493294523),
                Self::from_u128_const(327773836761295472749990895064997074991),
                Self::from_u128_const(198128310469225103564532344069124399),
                Self::from_u128_const(65176661250063127310677367247900067852),
                Self::from_u128_const(242342804780088945017155417130892677514),
                Self::from_u128_const(138772011260490117816252961574289306816),
                Self::from_u128_const(205253056393609005522875972501154885983),
                Self::from_u128_const(317726287660162658821387861477302583473),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(217250839138421353436318368084321759680),
                Self::from_u128_const(317754180356169049724161533948814551100),
                Self::from_u128_const(16927176668965923175402717746039624447),
                Self::from_u128_const(258776387831806339857021365896849098817),
                Self::from_u128_const(17666080074338456966664106913120137980),
                Self::from_u128_const(60009081516200663335631386860132791339),
                Self::from_u128_const(102991965940264533127899026339393950588),
                Self::from_u128_const(112331229927218020056263576011034372590),
                Self::from_u128_const(184500073728661779510508730900433841535),
                Self::from_u128_const(211218446533310416807092936054851981786),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(173925311393179455246569828224129260302),
                Self::from_u128_const(296308313587701766766948086293600070191),
                Self::from_u128_const(33332068644302616674122975055691889483),
                Self::from_u128_const(155900095362269519779319759163748677093),
                Self::from_u128_const(43587746736855930083301997797325514856),
                Self::from_u128_const(296423362206237654114472540790749486996),
                Self::from_u128_const(114177498896775655524413766364624920718),
                Self::from_u128_const(55022947539972640258572133274184718364),
                Self::from_u128_const(113051992297966524881852629333968671858),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(297062813223354907329411156269979989384),
                Self::from_u128_const(55498875102507815491353012386755245730),
                Self::from_u128_const(97183195234143136341179557816284787233),
                Self::from_u128_const(270403797531338209745567427038712884667),
                Self::from_u128_const(123713051752486943980447104415706581647),
                Self::from_u128_const(133020482301726714061969471043085869386),
                Self::from_u128_const(129084436268751443109719694773436356216),
                Self::from_u128_const(300999069130577813329649794063126094168),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(1645703777016437714629157206641955411),
                Self::from_u128_const(231496577504192395792668042882768762319),
                Self::from_u128_const(317726287660162658821387861477302583473),
                Self::from_u128_const(27694789911334405391595093561069647213),
                Self::from_u128_const(22687114254299160926038189888566784014),
                Self::from_u128_const(58546241224996357010262736068369977482),
                Self::from_u128_const(264487024855738888491702452631261417506),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(38037535346261701501342686448200276617),
                Self::from_u128_const(54221509729363911693681432243308123656),
                Self::from_u128_const(301991129608627453072761912641719839795),
                Self::from_u128_const(70357236220939224698835302321949477827),
                Self::from_u128_const(339250576658533255637023616542837909595),
                Self::from_u128_const(47859474030351277790005742802004690535),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(217480865654509432899360809558247575290),
                Self::from_u128_const(189903756104397162778830291913051146195),
                Self::from_u128_const(222867999970256714018398050712535064668),
                Self::from_u128_const(139517438828506211642716080863358198247),
                Self::from_u128_const(285320343925353838224981329933203993161),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(258795108754019427095027841722093167037),
                Self::from_u128_const(98205778530760675500084609155277246157),
                Self::from_u128_const(205350314264990556018588615100340325482),
                Self::from_u128_const(91685833721197891782118719076912795535),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(337885671867720762115972294340238537909),
                Self::from_u128_const(133312971165295752178238705787144490844),
                Self::from_u128_const(79865913147303941867309655175065324520),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(34075701874363500988951311760257950112),
                Self::from_u128_const(60671999173760487464442662968386560731),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
                Self::from_u128_const(333868580667653917453718037019227144272),
            ],
            [
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(0),
                Self::from_u128_const(1),
            ],
        ]
    }

    /// Twiddle the bits of alpha by the normalized subspace vanishing polynomials.
    ///
    /// Implements procedure TWIDDLE from Algorithm 1 in section 3.2 of [the paper][1].
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn twiddle(power: u32, mut coset: usize) -> Self {
        // unwrap safety: u32 will fit into a usize anywhere we are deploying
        let power: usize = power.try_into().expect("u32 too big for usize?");

        let mut accumulator = Self::ZERO;
        let mut position = 0;
        while coset > 0 {
            if coset & 1 == 1 {
                accumulator += Self::twiddle_array()[power][position];
            }
            coset >>= 1;
            position += 1;
        }

        accumulator
    }

    /// Implements procedure BUTTERFLY-FWD from Algorithm 1 in section 3.2 of [the paper][1].
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn fft_butterfly_forward(
        fft_array: &mut [Self],
        index: usize,
        recursive_len: usize,
        twiddle: Self,
    ) {
        fft_array[index] += twiddle * fft_array[index + recursive_len];
        fft_array[index + recursive_len] += fft_array[index];
    }

    /// Implements procedure BUTTERFLY-BWD from Algorithm 1 in section 3.2 of [the paper][1].
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn fft_butterfly_backward(
        fft_array: &mut [Self],
        index: usize,
        recursive_len: usize,
        twiddle: Self,
    ) {
        fft_array[index + recursive_len] -= fft_array[index];
        fft_array[index] -= twiddle * fft_array[index + recursive_len];
    }

    /// Implements procedure BUTTERFLY-DIAG from Algorithm 1 in section 3.2 of [the paper][1].
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn fft_butterfly_diagonal(
        fft_array: &mut [Self],
        index: usize,
        recursive_len: usize,
        twiddle: Self,
    ) {
        let prev_at_index = fft_array[index];

        fft_array[index] -= twiddle * fft_array[index + recursive_len];
        fft_array[index + recursive_len] += prev_at_index;
    }

    /// Implements procedure FFT and IFFT (depending on direction) from Algorithm 1 in section 3.2
    /// of [the paper][1].
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn fft(direction: Direction, power: u32, coset: usize, fft_array: &mut [Self]) {
        for mut curr_power in 0..power {
            // Forward FFT iterates over power..0
            if direction == Direction::Forward {
                curr_power = power - curr_power - 1;
            }
            let recursive_len = 2usize.pow(curr_power);
            // In the paper this loop is "for all u : 0 ≤ 2s · u < 2ℓ", but we only ever work with
            // increments of 2s so no need to keep track of u.
            for start in (0..2usize.pow(power)).step_by(2 * recursive_len) {
                let twiddle = Self::twiddle(curr_power, start + coset);
                for v in 0..recursive_len {
                    match direction {
                        Direction::Forward => Self::fft_butterfly_forward(
                            fft_array,
                            start + v,
                            recursive_len,
                            twiddle,
                        ),
                        Direction::Backward => Self::fft_butterfly_backward(
                            fft_array,
                            start + v,
                            recursive_len,
                            twiddle,
                        ),
                    };
                }
            }
        }
    }

    /// Perform a Fast Fourier Transform in the novel polynomial basis, in place.
    ///
    /// The first `nodes_count` elements of `fft_array` are evaluations of a polynomial in one
    /// variable of degree up to `nodes_count - 1`. The FFT is used to interpolate and evaluate it.
    ///
    /// On return, the first `nodes_count` elements of `fft_array` are coefficients of the
    /// polynomial and the remainder is evaluations of it at points `[nodes_count..fft_array.len()]`.
    ///
    /// `fft_array.len()` must be `2^power` and greater than `nodes_count`. `coset` is which coset
    /// to recurse on and twiddle with.
    ///
    /// Corresponds to Algorithm 2: Bidirectional-FFT in [the paper][1]. Their `k` is `nodes_count`
    /// here, their `i` is `power`, their alpha is `coset` and their `B` is `fft_array`.
    ///
    /// [1]: https://eprint.iacr.org/2024/2010.pdf
    fn bidirectional_fft(mut power: u32, coset: usize, nodes_count: usize, fft_array: &mut [Self]) {
        assert_eq!(
            fft_array.len(),
            2usize.pow(power),
            "length of fft_array must be 2^power"
        );
        assert!(nodes_count <= fft_array.len());

        if power > 0 {
            power -= 1;
            let recursive_len = 2usize.pow(power);
            assert_eq!(recursive_len, 1 << power);
            let twiddle = Self::twiddle(power, coset);
            if nodes_count < recursive_len {
                // Forward FFT: evaluate the polynomial
                for v in nodes_count..recursive_len {
                    Self::fft_butterfly_forward(fft_array, v, recursive_len, twiddle);
                }
                Self::bidirectional_fft(power, coset, nodes_count, &mut fft_array[..recursive_len]);
                for v in 0..nodes_count {
                    Self::fft_butterfly_diagonal(fft_array, v, recursive_len, twiddle);
                }
                Self::fft(
                    Direction::Forward,
                    power,
                    coset + recursive_len,
                    &mut fft_array[recursive_len..],
                );
            } else {
                // Inverse FFT: replace evaluations of the polynomial with coefficients
                Self::fft(
                    Direction::Backward,
                    power,
                    coset,
                    &mut fft_array[..recursive_len],
                );
                for v in (nodes_count - recursive_len)..recursive_len {
                    Self::fft_butterfly_diagonal(fft_array, v, recursive_len, twiddle);
                }
                Self::bidirectional_fft(
                    power,
                    coset + recursive_len,
                    nodes_count - recursive_len,
                    &mut fft_array[recursive_len..],
                );
                for v in 0..(nodes_count - recursive_len) {
                    Self::fft_butterfly_backward(fft_array, v, recursive_len, twiddle);
                }
            }
        }
    }
}

#[derive(Eq, PartialEq)]
enum Direction {
    Forward,
    Backward,
}

impl FieldElement for Field2_128 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(0b1);
    const SUMCHECK_P2: Self = Self(0b10);

    fn from_u128(value: u128) -> Self {
        Self(value)
    }

    fn square(&self) -> Self {
        Self(galois_square(self.0))
    }
}

impl CodecFieldElement for Field2_128 {
    const NUM_BITS: u32 = 128;
}

impl LagrangePolynomialFieldElement for Field2_128 {
    const SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(x).inverse().to_integer()
        Self::from_u128_const(170141183460469231731687303715884105795)
    };

    const ONE_MINUS_SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(1 - x).inverse().to_integer()
        Self::from_u128_const(340282366920938463463374607431768211330)
    };

    const SUMCHECK_P2_SQUARED_MINUS_SUMCHECK_P2_MUL_INV: Self = const {
        // Computed in SageMath:
        //
        // GF2 = GF(2)
        // x = polygen(GF2)
        // GF2_128.<x> = GF2.extension(x^128 + x^7 + x^2 + x + 1)
        // GF2_128(x^2 - x).inverse().to_integer()
        Self::from_u128_const(170141183460469231731687303715884105665)
    };

    fn mul_inv(&self) -> Self {
        // Compute the multiplicative inverse by exponentiating to the power (2^128 - 2). See
        // FieldP256::mul_inv() for an explanation of this technique.
        addition_chains::gf_2_128_m2::exp(*self)
    }

    type ExtendContext = ExtendContext;

    fn extend_precompute(nodes_len: usize, evaluations: usize) -> Self::ExtendContext {
        ExtendContext {
            nodes_len,
            evaluations,
        }
    }

    fn extend(nodes: &[Self], context: &Self::ExtendContext) -> Vec<Self> {
        assert_eq!(nodes.len(), context.nodes_len);
        // We first run the bidirectional FFT to interpolate the polynomial, then run forward FFTs
        // over as many coset as are needed to evaluate all the requested points.
        //
        // See "Details of Reed-Solomon encoding" in paper section 3.2.
        //
        // The FFT must run in an array whose size is a power of two.
        let fft_size = context.nodes_len.next_power_of_two();
        let power = fft_size.ilog2();

        let mut fft_vec = nodes.to_vec();
        fft_vec.resize(fft_size, Self::ZERO);

        // Run the bidirectional FFT to get context.nodes_len coefficients of the polynomial, then
        // fft_size - context.nodes_len evaluations of the polynomial in fft_vec.
        Self::bidirectional_fft(power, 0, context.nodes_len, &mut fft_vec);

        let mut out_vec = vec![Self::ZERO; context.evaluations];

        // Copy the provided evaluations from the nodes to the output
        out_vec[..nodes.len()].copy_from_slice(nodes);

        // Copy evaluations from the first coset, if any
        let range = nodes.len()..min(fft_size, context.evaluations);
        let fft_vec_evals = &mut fft_vec[range.clone()];
        out_vec[range].copy_from_slice(fft_vec_evals);

        // Zero out coefficients in fft_vec so we can use it for FFT again
        fft_vec_evals.fill(Self::ZERO);

        // Use the forward FFT over the remaining cosets, each of size 2^power, to compute the
        // remaining requested evaluations.
        for curr_power in (1..).map_while(|coset| {
            let curr_power = coset << power;
            if curr_power >= context.evaluations {
                None
            } else {
                Some(curr_power)
            }
        }) {
            // If there's enough room left in out_vec, we copy the coefficients from fft_vec into
            // the output vec and transform in place.
            //
            // If not, then this has to be the last iteration of the loop. We do the transform in
            // fft_vec. That will overwrite the coefficients, but that's okay: we don't need them
            // anymore after this iteration.
            if curr_power + fft_size <= context.evaluations {
                out_vec[curr_power..(fft_size + curr_power)].copy_from_slice(&fft_vec[..fft_size]);
                Self::fft(
                    Direction::Forward,
                    power,
                    curr_power,
                    &mut out_vec[curr_power..],
                );
            } else {
                Self::fft(Direction::Forward, power, curr_power, &mut fft_vec);
                out_vec[curr_power..context.evaluations]
                    .copy_from_slice(&fft_vec[..(context.evaluations - curr_power)]);
            }
        }

        out_vec
    }
}

impl Debug for Field2_128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Field2_128(0x{:032x})", self.0)
    }
}

impl Default for Field2_128 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for Field2_128 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Field2_128 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Field2_128 {}

impl From<u64> for Field2_128 {
    fn from(value: u64) -> Self {
        Self::from_u128(value as u128)
    }
}

impl TryFrom<&[u8]> for Field2_128 {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array_reference =
            <&[u8; 16]>::try_from(value).context("failed to decode Field2_128")?;
        Ok(Self(u128::from_le_bytes(*array_reference)))
    }
}

impl Codec for Field2_128 {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, anyhow::Error> {
        let mut buffer = [0u8; 16];
        bytes
            .read_exact(&mut buffer)
            .context("failed to read Field2_128 element")?;
        Ok(Self(u128::from_le_bytes(buffer)))
    }

    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        bytes.extend_from_slice(&self.0.to_le_bytes());
        Ok(())
    }
}

impl Add<&Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for Field2_128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Sub<&Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub<Self> for Field2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl SubAssign for Field2_128 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Mul<&Self> for Field2_128 {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self(galois_multiply(self.0, rhs.0))
    }
}

impl Mul<Self> for Field2_128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(galois_multiply(self.0, rhs.0))
    }
}

impl MulAssign for Field2_128 {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = galois_multiply(self.0, rhs.0);
    }
}

impl Neg for Field2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

#[derive(Copy, Clone)]
pub struct ExtendContext {
    nodes_len: usize,
    evaluations: usize,
}

#[cfg(target_arch = "aarch64")]
mod backend_aarch64;
mod backend_bit_slicing;
#[cfg(test)]
mod backend_naive_loop;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod backend_x86;

/// Cache for runtime CPU feature support detection.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
struct CachedFeatureFlag {
    /// Stores whether feature detection has been performed yet, and what the result was.
    ///
    /// Multiple threads are allowed to race to initialize this state.
    state: AtomicU8,

    /// Function that determines whether the specific feature is supported.
    callback: fn() -> bool,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
impl CachedFeatureFlag {
    const MASK_INITIALIZED: u8 = 0b01;
    const MASK_SUPPORTED: u8 = 0b10;

    pub const fn new(callback: fn() -> bool) -> Self {
        Self {
            state: AtomicU8::new(0),
            callback,
        }
    }

    pub fn get(&self) -> bool {
        let mut state = self.state.load(Ordering::Relaxed);

        if state & Self::MASK_INITIALIZED == 0 {
            let result = (self.callback)();
            state |= Self::MASK_INITIALIZED;
            if result {
                state |= Self::MASK_SUPPORTED;
            }
            self.state.fetch_or(state, Ordering::Relaxed);
        }

        state & Self::MASK_SUPPORTED != 0
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
    is_x86_feature_detected!("sse2") && is_x86_feature_detected!("pclmulqdq")
});
#[cfg(target_arch = "aarch64")]
static FEATURES: CachedFeatureFlag = CachedFeatureFlag::new(|| {
    is_aarch64_feature_detected!("neon") && is_aarch64_feature_detected!("aes")
});

/// Multiplies two GF(2^128) elements, represented as `u128`s.
///
/// This dispatches to an appropriate implementation depending on CPU support, or a fallback
/// implementation.
fn galois_multiply(x: u128, y: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if FEATURES.get() {
        return unsafe { backend_x86::galois_multiply(x, y) };
    }
    #[cfg(target_arch = "aarch64")]
    if FEATURES.get() {
        return unsafe { backend_aarch64::galois_multiply(x, y) };
    }
    backend_bit_slicing::galois_multiply(x, y)
}

/// Squares a GF(2^128) element, represented as a `u128`.
///
/// This dispatches to an appropriate implementation depending on CPU support, or a fallback
/// implementation.
fn galois_square(x: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if FEATURES.get() {
        return unsafe { backend_x86::galois_square(x) };
    }
    #[cfg(target_arch = "aarch64")]
    if FEATURES.get() {
        return unsafe { backend_aarch64::galois_square(x) };
    }
    backend_bit_slicing::galois_square(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::fields::field2_128::backend_aarch64;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use crate::fields::field2_128::backend_x86;
    use crate::fields::field2_128::{
        backend_bit_slicing, backend_naive_loop, galois_multiply, galois_square,
    };
    use rand::random;
    use std::{iter::repeat_with, ops::Range};
    use wasm_bindgen_test::wasm_bindgen_test;

    static ARGS: [u128; 8] = [
        u128::MIN,
        u128::MAX,
        0x5555_5555_5555_5555_5555_5555_5555_5555u128,
        0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128,
        0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFEu128,
        0x8000_0000_0000_0000_0000_0000_0000_0001u128,
        0x8000_0000_0000_0000_0000_0000_0000_0002u128,
        0x0000_0000_0000_0001_0000_0000_0000_0000u128,
    ];

    #[wasm_bindgen_test(unsupported = test)]
    fn compare_bit_slicing() {
        for (i, x) in ARGS.into_iter().enumerate() {
            for y in ARGS[i..].iter().copied() {
                let expected = backend_naive_loop::galois_multiply(x, y);
                let result = backend_bit_slicing::galois_multiply(x, y);
                assert_eq!(
                    expected, result,
                    "0x{x:x} * 0x{y:x}, 0x{expected:x} != 0x{result:x}"
                );
                let assoc_result = backend_bit_slicing::galois_multiply(y, x);
                assert_eq!(
                    expected, assoc_result,
                    "0x{x:x} * 0x{y:x}, 0x{expected:x} != 0x{assoc_result:x}"
                );
            }
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:x}^2, 0x{expected:x} != 0x{result:x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn feature_detection() {
        let result = galois_multiply(3, 3);
        assert_eq!(result, 5);
        let result = galois_square(3);
        assert_eq!(result, 5);
    }

    // This test vector is taken from the Intel white paper "Intel Carry-Less Multiplication
    // Instruction and its Usage for Computing the GCM Mode".
    const TEST_VECTOR_A: u128 = 0x7b5b54657374566563746f725d53475d;
    const TEST_VECTOR_B: u128 = 0x48692853686179295b477565726f6e5d;
    const TEST_VECTOR_PRODUCT: u128 = 0x40229a09a5ed12e7e4e10da323506d2;

    #[wasm_bindgen_test(unsupported = test)]
    fn test_vector_naive_loop() {
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = backend_naive_loop::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn test_vector_bit_slicing() {
        let result = backend_bit_slicing::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = backend_bit_slicing::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A);
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_vector_x86() {
        let result = unsafe { backend_x86::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = unsafe { backend_x86::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_vector_aarch64() {
        let result = unsafe { backend_aarch64::galois_multiply(TEST_VECTOR_A, TEST_VECTOR_B) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
        let result = unsafe { backend_aarch64::galois_multiply(TEST_VECTOR_B, TEST_VECTOR_A) };
        assert_eq!(result, TEST_VECTOR_PRODUCT);
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "nondeterministic test"]
    fn random_test_multiply_bit_slicing() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_naive_loop::galois_multiply(x, y);
            let result = backend_bit_slicing::galois_multiply(x, y);
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "nondeterministic test"]
    fn random_test_square_bit_slicing() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn random_test_multiply_x86() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_bit_slicing::galois_multiply(x, y);
            let result = unsafe { backend_x86::galois_multiply(x, y) };
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn random_test_square_x86() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_x86::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(target_arch = "aarch64")]
    fn random_test_multiply_aarch64() {
        for _ in 0..10_000 {
            let x = random();
            let y = random();
            let expected = backend_bit_slicing::galois_multiply(x, y);
            let result = unsafe { backend_aarch64::galois_multiply(x, y) };
            assert_eq!(
                expected, result,
                "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[ignore = "nondeterministic test"]
    #[cfg(target_arch = "aarch64")]
    fn random_test_square_aarch64() {
        for _ in 0..10_000 {
            let x = random();
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_aarch64::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[wasm_bindgen_test(unsupported = test)]
    #[ignore = "test is slow without optimization"]
    fn low_hamming_weight_bit_slicing() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_naive_loop::galois_multiply(x, y);
                let result = backend_bit_slicing::galois_multiply(x, y);
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_naive_loop::galois_square(x);
            let result = backend_bit_slicing::galois_square(x);
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn low_hamming_weight_x86() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_bit_slicing::galois_multiply(x, y);
                let result = unsafe { backend_x86::galois_multiply(x, y) };
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_x86::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn low_hamming_weight_aarch64() {
        for i in 0..128 {
            let x = 1 << i;
            for j in 0..128 {
                let y = 1 << j;
                let expected = backend_bit_slicing::galois_multiply(x, y);
                let result = unsafe { backend_aarch64::galois_multiply(x, y) };
                assert_eq!(
                    expected, result,
                    "0x{x:032x} * 0x{y:032x} returned 0x{result:032x} not 0x{expected:032x}"
                );
            }
            let expected = backend_bit_slicing::galois_square(x);
            let result = unsafe { backend_aarch64::galois_square(x) };
            assert_eq!(
                expected, result,
                "0x{x:032x}^2 returned 0x{result:032x} not 0x{expected:032x}"
            );
        }
    }

    #[test]
    fn twiddle_array() {
        // Print out the computed twiddle array as a literal so it can be copy-pasted into
        // Field2_128::twiddle_array
        println!("[");
        for row in Field2_128::compute_twiddle_array() {
            println!("[");
            for element in row {
                println!("Self::from_u128_const({}),", element.0);
            }
            println!("],")
        }
        print!("]");

        assert_eq!(
            Field2_128::twiddle_array(),
            Field2_128::compute_twiddle_array()
        );
    }

    #[test]
    fn extend_gf_2_128() {
        fn eval_horners_method(polynomial: &[Field2_128], eval_at: Range<u16>) -> Vec<Field2_128> {
            eval_at
                .map(|x| {
                    let x = Field2_128::inject(x);
                    let mut output = Field2_128::ZERO;

                    for coefficient in polynomial.iter().rev() {
                        output = output * x + *coefficient;
                    }

                    output
                })
                .collect()
        }

        // Interpolate to various numbers of evaluations, falling just before, just after or on
        // powers of two
        for requested_evaluations in [1, 63, 64, 65, 99, 128] {
            for polynomial_degree in 1..requested_evaluations {
                println!(
                    "degree {polynomial_degree} and requested evaluations {requested_evaluations}"
                );
                // Generate a random polynomial and evaluate nodes
                let polynomial: Vec<_> = repeat_with(|| Field2_128::inject(random()))
                    .take(polynomial_degree)
                    .collect();

                // Evaluate the polynomial using the slow method
                let expected =
                    eval_horners_method(&polynomial, 0..requested_evaluations.try_into().unwrap());

                // Interpolate from the nodes
                let extended = Field2_128::extend(
                    &expected[0..polynomial_degree],
                    &Field2_128::extend_precompute(polynomial_degree, requested_evaluations),
                );

                assert_eq!(
                    extended, expected,
                    "interpolation mismatch at degree {polynomial_degree} and requested \
                    evaluations {requested_evaluations}"
                );
            }
        }
    }
}
