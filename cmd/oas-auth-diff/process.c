#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <moonbit.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#define OAS_MAX_INPUT (16u * 1024u * 1024u)

MOONBIT_FFI_EXPORT void oas_auth_diff_exit(int32_t code) {
  exit(code);
}

MOONBIT_FFI_EXPORT void oas_auth_diff_stderr(const unsigned char *text, int32_t length) {
  fwrite(text, 1, (size_t)length, stderr);
  fputc('\n', stderr);
  fflush(stderr);
}

/* Borrowed paths and output buffers are retained only for this call. */
MOONBIT_FFI_EXPORT int32_t oas_auth_diff_read_bounded(
    const unsigned char *path, unsigned char *output) {
  FILE *file;
  int regular;
  int oversized;
  int capacity = Moonbit_array_length(output);
  if (capacity != OAS_MAX_INPUT + 1u) return -2;

#ifdef _WIN32
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      (const char *)path, -1, NULL, 0);
  if (!count) return -1;
  wchar_t *wide = malloc((size_t)count * sizeof(wchar_t));
  if (!wide) return -1;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      (const char *)path, -1, wide, count)) {
    free(wide);
    return -1;
  }
  file = _wfopen(wide, L"rb");
  free(wide);
  if (!file) return -1;
  struct _stat64 info;
  if (_fstat64(_fileno(file), &info) != 0) {
    fclose(file);
    return -2;
  }
  regular = (info.st_mode & _S_IFMT) == _S_IFREG;
  oversized = info.st_size > OAS_MAX_INPUT;
#else
  int descriptor = open((const char *)path, O_RDONLY | O_NONBLOCK);
  if (descriptor < 0) return -1;
  file = fdopen(descriptor, "rb");
  if (!file) {
    close(descriptor);
    return -1;
  }
  struct stat info;
  if (fstat(fileno(file), &info) != 0) {
    fclose(file);
    return -2;
  }
  regular = S_ISREG(info.st_mode);
  oversized = info.st_size > OAS_MAX_INPUT;
#endif

  if (!regular || oversized) {
    fclose(file);
    return regular ? -4 : -3;
  }
  /* The extra byte detects growth after stat without reading an unbounded file. */
  size_t length = fread(output, 1, (size_t)capacity, file);
  int failed = ferror(file);
  if (fclose(file) != 0) failed = 1;
  return failed ? -2 : (int32_t)length;
}
