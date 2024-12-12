#pragma once


template<typename T>
class Buffer {

private:

    /**
     * @brief Pointer to wrapped buffer.
     */
    T *data_;

    /**
     * @brief Buffer size.
     */
    uint32_t size_;

    /**
     * @brief When true, the wrapper creates new buffer instead of housing an existing one.
     */
    bool internal = false;

public:

    /**
     * @brief Construct a new Buffer object by allocating memory w.r.t. to the given size.
     *
     * @param s_arg size of buffer
     */
    explicit Buffer(uint32_t s_arg) {
        data_ = new T[s_arg];
        size_ = s_arg;
        internal = true;
    }

    /**
     * @brief Construct a new Buffer object as a wrapper for an already existing buffer.
     *
     * @param d_arg pointer to existing buffer
     * @param s_arg size of buffer
     */
    Buffer(T *d_arg, uint32_t s_arg) {
        data_ = d_arg;
        size_ = s_arg;
    }

    /**
     * @brief When destroying the object, also release any memory, if allocated.
     */
    ~Buffer() {
        if (internal) {
            delete[] data_;
        }
    }

    /**
     * @brief Pointer to the wrapped buffer.
     *
     * @return T* pointer of type T
     */
    T *data() const {
        return data_;
    }

    /**
     * @brief Size of wrapped buffer.
     *
     * @return uint32_t size
     */
    [[nodiscard]] uint32_t size() const {
        return size_;
    }
};
