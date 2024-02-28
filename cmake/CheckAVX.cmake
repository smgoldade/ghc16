#Source: https://gist.github.com/jollyjonson/9031448feaf7e6e034ee3918a606910a
macro(Check_for_AVX)
    set(AVX_FLAGS)

    include(CheckCXXSourceRuns)
    set(CMAKE_REQUIRED_FLAGS)

    # Check for AVX
    if (MSVC)
        if (NOT MSVC_VERSION LESS 1600)
            set(CMAKE_REQUIRED_FLAGS "/arch:AVX")
        endif ()
    else ()
        set(CMAKE_REQUIRED_FLAGS "-mavx")
    endif ()

    check_cxx_source_runs("
        #include <immintrin.h>
        int main()
        {
          __m256 a, b, c;
          const float src[8] = { 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f };
          float dst[8];
          a = _mm256_loadu_ps( src );
          b = _mm256_loadu_ps( src );
          c = _mm256_add_ps( a, b );
          _mm256_storeu_ps( dst, c );
          for( int i = 0; i < 8; i++ ){
            if( ( src[i] + src[i] ) != dst[i] ){
              return -1;
            }
          }
          return 0;
        }"
            HAVE_AVX_EXTENSIONS)

    # Check for AVX2
    if (MSVC)
        if (NOT MSVC_VERSION LESS 1800)
            set(CMAKE_REQUIRED_FLAGS "/arch:AVX2")
        endif ()
    else ()
        set(CMAKE_REQUIRED_FLAGS "-mavx2")
    endif ()

    check_cxx_source_runs("
        #include <immintrin.h>
        int main()
        {
          __m256i a, b, c;
          const int src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
          int dst[8];
          a =  _mm256_loadu_si256( (__m256i*)src );
          b =  _mm256_loadu_si256( (__m256i*)src );
          c = _mm256_add_epi32( a, b );
          _mm256_storeu_si256( (__m256i*)dst, c );
          for( int i = 0; i < 8; i++ ){
            if( ( src[i] + src[i] ) != dst[i] ){
              return -1;
            }
          }
          return 0;
        }"
            HAVE_AVX2_EXTENSIONS)

    # Set Flags according to check results
    if (MSVC)
        if (HAVE_AVX2_EXTENSIONS AND NOT MSVC_VERSION LESS 1800)
            set(AVX_FLAGS /arch:AVX2)
        elseif (HAVE_AVX_EXTENSIONS AND NOT MSVC_VERSION LESS 1600)
            set(AVX_FLAGS /arch:AVX)
        endif ()
    else ()
        if (HAVE_AVX2_EXTENSIONS)
            set(AVX_FLAGS -mavx2)
        elseif (HAVE_AVX_EXTENSIONS)
            set(AVX_FLAGS -mavx)
        endif ()
    endif ()

    message(STATUS "AVX Flags: ${AVX_FLAGS}")
endmacro(Check_for_AVX)