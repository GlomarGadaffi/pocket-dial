/*
 * mix_sum4_s16.S  —  ESP32-S3 PIE (Xtensa LX7) saturating int16 frame sum.
 *
 *   out[i] = sat16( a[i] + b[i] + c[i] + d[i] )   for i in [0, frameLen)
 *
 * This is the small-conference fast path: to give port P "everyone but itself,"
 * pass P's up-to-four active peers as a,b,c,d (zero-frame any unused slot). A
 * <=5-way conference needs NO int32 accumulator and NO minus-self subtraction —
 * you simply never form the all-inclusive sum, so the over-saturation trap can't
 * occur. For >5-way, chain this kernel (mix one group to a temp, add the next);
 * saturating sum is a valid mix. See docs/CONFERENCE_MIXER.md §6.
 *
 * INSTRUCTIONS USED — all confirmed real on ESP32-S3:
 *   ee.vld.128.ip qu, ars, imm   load 128b, post-inc pointer by imm (step 16)
 *   ee.vadds.s16  qa, qb, qc      8-lane int16 saturating add
 *   ee.vst.128.ip qu, ars, imm    store 128b, post-inc pointer by imm
 *   (vadds.s16 pattern verified against esp-dsp dsps_add_s16_aes3.S and the
 *    ESP32-S3 TRM extended-instruction-set chapter.)
 *
 * ALIGNMENT (hard requirement): a,b,c,d,out must be 16-byte aligned and frameLen
 *   a multiple of 8. ee.vld/vst.128 ignore the low 4 address bits — misalignment
 *   silently reads/writes the wrong window. FRAME=160 -> 20 iterations, 320 B,
 *   both satisfied. Declare the C-side buffers `alignas(16)` (MixBus.cpp does).
 *
 * C prototype (extern "C"):
 *   void mix_sum4_s16(int16_t* out, const int16_t* a, const int16_t* b,
 *                     const int16_t* c, const int16_t* d, int frameLen);
 *
 * Windowed ABI argument registers:  a2=out a3=a a4=b a5=c a6=d a7=frameLen
 */

/*
 * BUILD GUARD — the other half of the opt-in (issue #145).
 *
 * mix_kernels_scalar.cpp:7/:42 wraps its portable stand-in in the inverse
 * #ifndef POCKETDIAL_MIXBUS_PIE, so defining the macro switches the scalar
 * mix_sum4_s16 OFF. Nothing switched THIS one on or off, so only one direction
 * of the toggle existed: with the macro undefined and both files compiled, the
 * linker saw two definitions of the symbol.
 * Only the fact that no target lists this .S kept them apart — CMake
 * enumerates sources explicitly (main/CMakeLists.txt:122,
 * tests/CMakeLists.txt:247). A build that globs src/** recursively picks up
 * both and the link fails:
 *   ld: mix_sum4_s16.S.o: multiple definition of mix_sum4_s16;
 *       mix_kernels_scalar.cpp.o: first defined here      [arduino-cli, #145]
 *
 * A capital-S .S is run through the C preprocessor by GCC (-x
 * assembler-with-cpp), so #ifdef is the right gate here rather than a CMake
 * condition: it keeps the toggle in one place for anyone who glob-builds.
 * The guard brackets the ENTIRE .text/.align/.global/.type/.size block, so no
 * directive is split across it and the text GAS sees when the macro is defined
 * is identical, once cpp has run, to what was proven to assemble. When the
 * macro is undefined cpp hands GAS an empty translation unit, which assembles
 * to an object that simply exports no symbols.
 */
#ifdef POCKETDIAL_MIXBUS_PIE

    .text
    .align  4
    .global mix_sum4_s16
    .type   mix_sum4_s16,@function

mix_sum4_s16:
    entry   a1, 16              /* windowed prologue, 16 B frame                */
    srai    a7, a7, 3           /* a7 = frameLen / 8  (128-bit chunks)          */
    loopnez a7, .Lend           /* HW loop a7 times; skip body if a7 == 0       */

    ee.vld.128.ip q0, a3, 16    /* q0 = a[0..7],  a3 += 16                       */
    ee.vld.128.ip q1, a4, 16    /* q1 = b[0..7],  a4 += 16                       */
    ee.vadds.s16  q0, q0, q1    /* q0 = sat(a + b)                              */
    ee.vld.128.ip q1, a5, 16    /* q1 = c[0..7],  a5 += 16                       */
    ee.vadds.s16  q0, q0, q1    /* q0 = sat(a + b + c)                          */
    ee.vld.128.ip q1, a6, 16    /* q1 = d[0..7],  a6 += 16                       */
    ee.vadds.s16  q0, q0, q1    /* q0 = sat(a + b + c + d)                      */
    ee.vst.128.ip q0, a2, 16    /* out[0..7] = q0, a2 += 16                      */

.Lend:
    retw.n                      /* windowed epilogue / return                   */

    .size   mix_sum4_s16, .-mix_sum4_s16

#endif /* POCKETDIAL_MIXBUS_PIE */
