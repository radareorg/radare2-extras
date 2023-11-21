

struct gguf_str {
    uint64_t n;  // GGUFv2
    char * data;
};

enum {
    GGUF_TYPE_UINT8 = 0,
    GGUF_TYPE_INT8 = 1,
    GGUF_TYPE_UINT16,
    GGUF_TYPE_INT16,
    GGUF_TYPE_UINT32 = 4,
    GGUF_TYPE_INT32,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL,
    GGUF_TYPE_STRING = 8,
    GGUF_TYPE_UINT64 = 9,
    GGUF_TYPE_INT64 = 10,
    GGUF_TYPE_FLOAT64,
    GGUF_TYPE_ARRAY
};
static const size_t GGUF_TYPE_SIZE[GGUF_TYPE_COUNT] = {
    [GGUF_TYPE_UINT8]   = sizeof(uint8_t), // 0
    [GGUF_TYPE_INT8]    = sizeof(int8_t), // 1
    [GGUF_TYPE_UINT16]  = sizeof(uint16_t), // 2
    [GGUF_TYPE_INT16]   = sizeof(int16_t), // 3
    [GGUF_TYPE_UINT32]  = sizeof(uint32_t), // 4
    [GGUF_TYPE_INT32]   = sizeof(int32_t), // 5
    [GGUF_TYPE_FLOAT32] = sizeof(float), // 6
    [GGUF_TYPE_BOOL]    = sizeof(bool), // 7
    [GGUF_TYPE_STRING]  = sizeof(struct gguf_str), // 8
    [GGUF_TYPE_UINT64]  = sizeof(uint64_t), // 9
    [GGUF_TYPE_INT64]   = sizeof(int64_t), // 10
    [GGUF_TYPE_FLOAT64] = sizeof(double), // 11
    [GGUF_TYPE_ARRAY]   = 0, // undefined
};
static_assert(GGUF_TYPE_COUNT == 13, "GGUF_TYPE_COUNT != 13");

static const char * GGUF_TYPE_NAME[GGUF_TYPE_COUNT] = {
    [GGUF_TYPE_UINT8]   = "u8",
    [GGUF_TYPE_INT8]    = "i8",
    [GGUF_TYPE_UINT16]  = "u16",
    [GGUF_TYPE_INT16]   = "i16",
    [GGUF_TYPE_UINT32]  = "u32",
    [GGUF_TYPE_INT32]   = "i32",
    [GGUF_TYPE_FLOAT32] = "f32",
    [GGUF_TYPE_BOOL]    = "bool",
    [GGUF_TYPE_STRING]  = "str",
    [GGUF_TYPE_ARRAY]   = "arr",
    [GGUF_TYPE_UINT64]  = "u64",
    [GGUF_TYPE_INT64]   = "i64",
    [GGUF_TYPE_FLOAT64] = "f64",
};
static_assert(GGUF_TYPE_COUNT == 13, "GGUF_TYPE_COUNT != 13");

union gguf_value {
    uint8_t  uint8;
    int8_t   int8;
    uint16_t uint16;
    int16_t  int16;
    uint32_t uint32;
    int32_t  int32;
    float    float32;
    uint64_t uint64;
    int64_t  int64;
    double   float64;
    bool     bool_;

    struct gguf_str str;

    struct {
        enum gguf_type type;

        uint64_t n;  // GGUFv2
        void * data;
    } arr;
};

struct gguf_kv {
    struct gguf_str key;

    enum  gguf_type  type;
    union gguf_value value;
};

struct gguf_header {
    char magic[4];
    uint32_t version;
    uint64_t n_tensors; // GGUFv2
    uint64_t n_kv;      // GGUFv2
};

struct gguf_tensor_info {
    struct gguf_str name;

    uint32_t n_dims;
    uint64_t ne[GGML_MAX_DIMS];

    enum ggml_type type;

    uint64_t offset; // offset from start of `data`, must be a multiple of `ALIGNMENT`

    // for writing API
    const void * data;
    size_t size;
};

struct gguf_context {
    struct gguf_header header;

    struct gguf_kv          * kv;
    struct gguf_tensor_info * infos;

    size_t alignment;
    size_t offset;    // offset of `data` from beginning of file
    size_t size;      // size of `data` in bytes

    //uint8_t * padding;
    void * data;
};
