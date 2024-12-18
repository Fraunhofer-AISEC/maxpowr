/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  KeyMaterial.h
 *
 *  Creates sample key material for demonstration purposes.
 *
 *  All Rights Reserved.
 */


#pragma once


class KeyMaterial {

public:
    static constexpr unsigned char p_p[] = {199, 122, 145, 150, 162, 209, 187, 108, 236, 235, 171, 77, 143, 199, 90,
                                            191, 123, 102, 47, 181, 192, 252, 208, 60, 85, 201, 9, 235, 226, 119, 153,
                                            121, 78, 105, 111, 108, 8, 150, 94, 66, 154, 167, 33, 49, 47, 98, 55, 220,
                                            146, 12, 89, 2, 175, 68, 205, 222, 96, 54, 137, 61, 181, 122, 212, 62, 13,
                                            158, 32, 104, 183, 113, 246, 62, 13, 137, 30, 45, 132, 172, 6, 178, 179,
                                            131, 71, 103, 130, 76, 39, 69, 110, 92, 235, 71, 111, 91, 152, 170, 152,
                                            125, 231, 117, 246, 250, 186, 195, 30, 85, 97, 250, 195, 177, 144, 86, 198,
                                            175, 132, 59, 193, 40, 58, 104, 180, 42, 9, 88, 253, 47, 79, 2, 140, 227,
                                            185, 20, 126, 109, 177, 189, 244, 140, 228, 97, 126, 106, 76, 113, 85, 82,
                                            128, 137, 48, 215, 69, 245, 48, 52, 19, 193, 137, 76, 10, 109, 38, 253, 224,
                                            127, 95, 157, 239, 97, 248, 75, 193, 109, 142, 124, 162, 24, 229, 160, 196,
                                            138, 107, 196, 59, 250, 111, 168, 151, 91, 247, 186, 203, 238, 0, 112, 95,
                                            112, 0, 0, 0, 0, 0, 153, 199, 204, 255, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 3, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 31, 0, 0, 255, 255, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static constexpr unsigned char p_q[] = {141, 11, 103, 41, 141, 133, 127, 178, 131, 6, 48, 205, 242, 155, 123, 69,
                                            111, 20, 45, 58, 227, 146, 109, 76, 221, 68, 248, 8, 30, 127, 132, 218, 222,
                                            81, 17, 20, 16, 93, 88, 0, 110, 210, 22, 238, 219, 38, 198, 202, 58, 118,
                                            136, 133, 146, 0, 22, 90, 89, 45, 178, 136, 80, 168, 167, 13, 68, 197, 112,
                                            223, 208, 171, 146, 224, 108, 56, 25, 100, 151, 72, 246, 200, 145, 78, 240,
                                            145, 96, 104, 127, 103, 90, 4, 151, 239, 223, 95, 134, 217, 36, 203, 47,
                                            239, 229, 183, 1, 203, 196, 112, 222, 234, 158, 215, 93, 37, 143, 250, 99,
                                            102, 131, 198, 85, 92, 116, 38, 63, 150, 30, 159, 173, 180, 29, 198, 172,
                                            124, 18, 84, 104, 70, 93, 201, 176, 173, 224, 232, 40, 44, 247, 26, 251,
                                            250, 179, 213, 135, 227, 44, 237, 164, 126, 172, 39, 112, 14, 143, 209, 4,
                                            49, 109, 108, 59, 4, 183, 64, 13, 11, 193, 55, 192, 94, 138, 153, 106, 156,
                                            219, 157, 6, 132, 101, 185, 197, 250, 118, 152, 160, 218, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 235, 88, 12, 31, 127,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                            255, 255, 255, 255, 255, 255, 255, 50, 48, 50, 49, 45, 101, 110, 99, 108,
                                            97, 118, 101, 45, 109, 101, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            86, 73, 67, 69, 95, 86, 69, 82};
    static constexpr unsigned char p_dmp1[] = {167, 170, 130, 12, 87, 213, 243, 185, 79, 204, 212, 197, 214, 223, 28,
                                               110, 31, 98, 178, 89, 178, 14, 148, 225, 78, 33, 123, 204, 212, 133, 26,
                                               30, 141, 189, 66, 186, 200, 242, 104, 206, 196, 152, 190, 193, 11, 169,
                                               44, 131, 237, 230, 137, 37, 115, 99, 121, 212, 124, 186, 40, 167, 74,
                                               155, 13, 226, 148, 151, 26, 228, 45, 23, 143, 84, 28, 128, 107, 196, 53,
                                               105, 13, 170, 101, 9, 179, 91, 151, 250, 221, 47, 31, 235, 137, 111, 126,
                                               158, 164, 59, 79, 118, 206, 109, 8, 123, 207, 98, 38, 153, 236, 24, 157,
                                               112, 177, 209, 183, 180, 68, 218, 114, 157, 158, 149, 189, 36, 86, 28,
                                               221, 96, 192, 19, 39, 144, 55, 165, 25, 255, 177, 117, 99, 49, 209, 152,
                                               202, 44, 66, 172, 109, 189, 184, 89, 159, 112, 203, 113, 227, 225, 216,
                                               59, 69, 9, 5, 41, 173, 254, 195, 89, 235, 111, 21, 67, 35, 200, 231, 136,
                                               226, 38, 32, 43, 207, 178, 131, 171, 212, 159, 124, 49, 111, 104, 162,
                                               67, 154, 161, 202, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 235, 88, 12, 31, 127,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
                                               255, 255, 255, 255, 255, 255, 255, 255, 50, 48, 50, 49, 45, 101, 110, 99,
                                               108, 97, 118, 101, 45, 109, 101, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 86, 73, 67, 69, 95, 86, 69, 82, 83, 73, 79, 78, 95, 50, 46,
                                               49, 0, 0, 0, 0, 0, 0, 0, 0};
    static constexpr unsigned char p_dmq1[] = {137, 204, 154, 231, 164, 88, 106, 151, 232, 216, 111, 36, 141, 74, 220,
                                               43, 210, 228, 63, 73, 200, 148, 122, 250, 52, 211, 1, 96, 128, 74, 40, 4,
                                               28, 146, 144, 228, 145, 124, 109, 17, 87, 86, 57, 164, 211, 19, 184, 39,
                                               1, 64, 213, 30, 123, 84, 196, 70, 162, 180, 232, 92, 147, 41, 111, 189,
                                               119, 80, 29, 26, 159, 89, 221, 96, 253, 212, 154, 252, 63, 144, 189, 195,
                                               62, 128, 25, 219, 125, 44, 26, 172, 197, 27, 37, 217, 7, 101, 178, 77,
                                               166, 171, 146, 242, 74, 251, 30, 105, 65, 21, 51, 115, 161, 236, 33, 54,
                                               72, 215, 202, 231, 69, 250, 152, 127, 43, 209, 146, 39, 103, 93, 166, 33,
                                               17, 179, 84, 211, 82, 91, 93, 116, 49, 43, 168, 49, 34, 214, 238, 27,
                                               177, 46, 142, 24, 121, 77, 74, 71, 158, 223, 104, 26, 153, 176, 117, 198,
                                               168, 220, 113, 32, 123, 28, 135, 221, 29, 236, 127, 33, 8, 227, 233, 115,
                                               114, 126, 45, 98, 146, 160, 196, 116, 5, 86, 4, 241, 90, 105, 245, 40, 0,
                                               112, 95, 100, 109, 113, 49, 0, 0, 153, 199, 204, 255, 127, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 3, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 31,
                                               0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0};
    static constexpr unsigned char p_iqmp[] = {136, 136, 203, 167, 231, 44, 203, 78, 56, 214, 168, 19, 26, 202, 107, 71,
                                               243, 147, 158, 239, 22, 92, 116, 159, 163, 239, 143, 150, 144, 224, 40,
                                               138, 160, 200, 115, 202, 10, 211, 190, 58, 103, 186, 191, 93, 52, 211,
                                               242, 46, 13, 93, 122, 29, 10, 56, 193, 172, 224, 185, 65, 195, 198, 130,
                                               177, 60, 252, 79, 146, 65, 47, 101, 154, 174, 31, 188, 78, 238, 1, 79,
                                               189, 237, 46, 101, 233, 139, 19, 249, 130, 104, 152, 164, 239, 77, 217,
                                               150, 120, 57, 148, 219, 176, 184, 39, 24, 169, 149, 177, 225, 148, 17,
                                               139, 249, 147, 17, 80, 28, 254, 99, 255, 5, 52, 205, 196, 181, 108, 205,
                                               199, 72, 69, 100, 201, 159, 74, 96, 49, 82, 157, 38, 21, 43, 198, 71, 10,
                                               114, 11, 193, 2, 218, 193, 18, 136, 239, 176, 42, 25, 200, 172, 22, 180,
                                               132, 6, 113, 25, 62, 149, 68, 197, 232, 135, 56, 228, 194, 220, 154, 116,
                                               189, 31, 13, 66, 20, 0, 20, 188, 66, 14, 57, 131, 156, 237, 54, 209, 185,
                                               239, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 31, 0, 0,
                                               255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 224, 235, 88, 12, 31, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               255, 255, 255, 255, 255, 255, 255, 255};
    static constexpr int n_byte_size = 384;
    static constexpr long pub_e = 65537;
};
