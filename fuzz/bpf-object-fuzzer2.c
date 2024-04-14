#include "libbpf.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct bpf_object *obj = NULL;
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
    };

    if (Size < sizeof(struct bpf_object_open_opts))
        return 0;

    // Copy the first sizeof(struct bpf_object_open_opts) bytes of Data into opts.
    memcpy(&opts, Data, sizeof(struct bpf_object_open_opts));

    // Increment Data and decrement Size by sizeof(struct bpf_object_open_opts).
    Data += sizeof(struct bpf_object_open_opts);
    Size -= sizeof(struct bpf_object_open_opts);

    // Call the function to be fuzzed with the remaining data.
    obj = bpf_object__open_mem(Data, Size, &opts);

    // If the object was successfully created, clean it up.
    if (obj)
        bpf_object__close(obj);

    return 0;
}