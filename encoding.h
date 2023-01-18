#ifndef LUPA_ENCODING_H_
#define LUPA_ENCODING_H_

#define _DATA_BYTE_CONST(data, pos) \
    ((uint8_t)(((const uint8_t *)(data))[(pos)]))

#define _DATA_BYTE(data, pos) \
    (((uint8_t *)(data))[(pos)])

#define PULL_BE_U8(data, pos) \
    (_DATA_BYTE_CONST(data, pos))

#define PULL_BE_U16(data, pos) \
    ((((uint16_t)(PULL_BE_U8(data, pos))) << 8) | (uint16_t)PULL_BE_U8(data, (pos) + 1))

#define PULL_BE_U32(data, pos) \
    ((((uint32_t)PULL_BE_U16(data, pos)) << 16) | (uint32_t)(PULL_BE_U16(data, (pos) + 2)))

#define PULL_BE_U64(data, pos) \
    ((((uint64_t)PULL_BE_U32(data, pos)) << 32) | (uint64_t)(PULL_BE_U32(data, (pos) + 4)))


#define PUSH_BE_U8(data, pos, val) \
    (_DATA_BYTE(data, pos) = ((uint8_t)(val)))

#define PUSH_BE_U16(data, pos, val) \
    (PUSH_BE_U8((data), (pos), (uint8_t)(((uint16_t)(val)) >> 8)), PUSH_BE_U8((data), (pos) + 1, (uint8_t)((val) & 0xff)))

#define PUSH_BE_U32(data, pos, val) \
    (PUSH_BE_U16((data), (pos), (uint16_t)(((uint32_t)(val)) >> 16)), PUSH_BE_U16((data), (pos) + 2, (uint16_t)((val) & 0xffff)))

#define PUSH_BE_U64(data, pos, val) \
    (PUSH_BE_U32((data), (pos), (uint32_t)(((uint64_t)(val)) >> 32)), PUSH_BE_U32((data), (pos) + 4, (uint32_t)((val) & 0xffffffff)))

#endif
