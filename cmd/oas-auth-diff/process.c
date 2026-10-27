#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
#define OAS_MAX_PATH 262144u

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

#ifdef _WIN32
static wchar_t *oas_wide(const unsigned char *path) {
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      (const char *)path, -1, NULL, 0);
  if (!count || count > 32768) return NULL;
  wchar_t *wide = malloc((size_t)count * sizeof(wchar_t));
  if (!wide) return NULL;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
      (const char *)path, -1, wide, count)) {
    free(wide);
    return NULL;
  }
  for (int i = 0; wide[i]; ++i) if (wide[i] == L'/') wide[i] = L'\\';
  return wide;
}

static int oas_local_drive(const wchar_t *path) {
  int valid = ((path[0] >= L'A' && path[0] <= L'Z') ||
      (path[0] >= L'a' && path[0] <= L'z')) &&
      path[1] == L':' && path[2] == L'\\';
  if (!valid) return 0;
  wchar_t drive[4] = { path[0], L':', L'\\', 0 };
  return GetDriveTypeW(drive) != DRIVE_REMOTE;
}

static wchar_t *oas_final_path(HANDLE handle) {
  wchar_t *path = malloc(32768u * sizeof(wchar_t));
  if (!path) return NULL;
  DWORD length = GetFinalPathNameByHandleW(handle, path, 32768,
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!length || length >= 32768 || wcsncmp(path, L"\\\\?\\", 4) != 0 ||
      !oas_local_drive(path + 4)) {
    free(path);
    return NULL;
  }
  memmove(path, path + 4, ((size_t)length - 3u) * sizeof(wchar_t));
  return path;
}

static int oas_write_wide_path(const wchar_t *path, unsigned char *output) {
  int capacity = Moonbit_array_length(output);
  int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
      path, -1, NULL, 0, NULL, NULL);
  if (!length || length > capacity) return -2;
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
      path, -1, (char *)output, capacity, NULL, NULL)) return -2;
  return length - 1;
}

static int oas_same_path(const wchar_t *left, const wchar_t *right) {
  return CompareStringOrdinal(left, -1, right, -1, TRUE) == CSTR_EQUAL;
}

static int oas_within(const wchar_t *root, const wchar_t *path) {
  size_t length = wcslen(root);
  while (length > 3 && root[length - 1] == L'\\') --length;
  return wcslen(path) > length &&
      CompareStringOrdinal(root, (int)length, path, (int)length, TRUE) == CSTR_EQUAL &&
      (root[length - 1] == L'\\' || path[length] == L'\\');
}

MOONBIT_FFI_EXPORT int32_t oas_auth_diff_canonical(
    const unsigned char *input, unsigned char *output, int32_t directory) {
  wchar_t *path = oas_wide(input);
  if (!path) return -2;
  if (!oas_local_drive(path)) { free(path); return -5; }
  HANDLE handle = CreateFileW(path, 0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  free(path);
  if (handle == INVALID_HANDLE_VALUE) return -1;
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(handle, &info) || GetFileType(handle) != FILE_TYPE_DISK ||
      ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != (directory != 0)) {
    CloseHandle(handle);
    return -3;
  }
  wchar_t *final = oas_final_path(handle);
  CloseHandle(handle);
  if (!final) return -5;
  int result = oas_write_wide_path(final, output);
  free(final);
  return result;
}

MOONBIT_FFI_EXPORT int32_t oas_auth_diff_read_confined(
    const unsigned char *root_input, const unsigned char *relative_input,
    unsigned char *output, unsigned char *canonical) {
  if (Moonbit_array_length(output) != OAS_MAX_INPUT + 1u) return -2;
  wchar_t *root = oas_wide(root_input);
  wchar_t *relative = oas_wide(relative_input);
  if (!root || !relative) { free(root); free(relative); return -2; }
  if (!oas_local_drive(root) || relative[0] == L'\\' || wcschr(relative, L':')) {
    free(root); free(relative); return -5;
  }
  HANDLE root_handle = CreateFileW(root, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (root_handle == INVALID_HANDLE_VALUE) { free(root); free(relative); return -1; }
  BY_HANDLE_FILE_INFORMATION info;
  wchar_t *root_final = oas_final_path(root_handle);
  int root_ok = root_final && oas_same_path(root, root_final) &&
      GetFileInformationByHandle(root_handle, &info) &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
      !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
  free(root_final);
  if (!root_ok) {
    CloseHandle(root_handle); free(root); free(relative); return -5;
  }
  size_t root_length = wcslen(root);
  size_t relative_length = wcslen(relative);
  if (root_length + relative_length + 2u > 32768u) {
    CloseHandle(root_handle); free(root); free(relative); return -2;
  }
  wchar_t *full = malloc((root_length + relative_length + 2u) * sizeof(wchar_t));
  if (!full) { CloseHandle(root_handle); free(root); free(relative); return -2; }
  wcscpy(full, root);
  size_t used = root_length;
  HANDLE file = INVALID_HANDLE_VALUE;
  int result = -5;
  wchar_t *part = relative;
  for (;;) {
    wchar_t *separator = wcschr(part, L'\\');
    if (separator) *separator = 0;
    if (!*part || wcscmp(part, L".") == 0 || wcscmp(part, L"..") == 0) break;
    if (used && full[used - 1] != L'\\') full[used++] = L'\\';
    wcscpy(full + used, part);
    used += wcslen(part);
    int last = separator == NULL;
    file = CreateFileW(full, last ? GENERIC_READ : 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) { result = -1; break; }
    if (!GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { result = -5; break; }
    if (!last) {
      if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { result = -3; break; }
      CloseHandle(file);
      file = INVALID_HANDLE_VALUE;
      part = separator + 1;
      continue;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || GetFileType(file) != FILE_TYPE_DISK) {
      result = -3; break;
    }
    wchar_t *final = oas_final_path(file);
    if (!final || !oas_within(root, final)) { free(final); result = -5; break; }
    result = oas_write_wide_path(final, canonical);
    free(final);
    if (result < 0) break;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size)) { result = -2; break; }
    if (size.QuadPart > OAS_MAX_INPUT) { result = -4; break; }
    DWORD count;
    result = ReadFile(file, output, OAS_MAX_INPUT + 1u, &count, NULL) ? (int32_t)count : -2;
    break;
  }
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  CloseHandle(root_handle);
  free(full); free(root); free(relative);
  return result;
}
#else
static int oas_write_path(const char *path, unsigned char *output) {
  size_t length = strlen(path);
  if (length + 1u > (size_t)Moonbit_array_length(output)) return -2;
  memcpy(output, path, length + 1u);
  return (int)length;
}

MOONBIT_FFI_EXPORT int32_t oas_auth_diff_canonical(
    const unsigned char *input, unsigned char *output, int32_t directory) {
  char *path = realpath((const char *)input, NULL);
  if (!path) return -1;
  int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (descriptor < 0) { free(path); return -1; }
  struct stat info;
  int valid = fstat(descriptor, &info) == 0 &&
      (directory ? S_ISDIR(info.st_mode) : S_ISREG(info.st_mode));
  close(descriptor);
  int result = valid ? oas_write_path(path, output) : -3;
  free(path);
  return result;
}

static int oas_component(const char *part) {
  return *part && strcmp(part, ".") != 0 && strcmp(part, "..") != 0;
}

/* Walk from an open root descriptor. No intermediate or final symlink is followed. */
static int oas_walk(int descriptor, char *parts, int directory) {
  char *part = parts;
  for (;;) {
    char *separator = strchr(part, '/');
    if (separator) *separator = 0;
    if (!oas_component(part)) { close(descriptor); return -5; }
    int last = separator == NULL;
    int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    if (!last || directory) flags |= O_DIRECTORY;
    int next = openat(descriptor, part, flags);
    int error = errno;
    close(descriptor);
    if (next < 0) return error == ELOOP ? -5 : error == ENOTDIR ? -3 : -1;
    descriptor = next;
    if (last) return descriptor;
    part = separator + 1;
  }
}

MOONBIT_FFI_EXPORT int32_t oas_auth_diff_read_confined(
    const unsigned char *root_input, const unsigned char *relative_input,
    unsigned char *output, unsigned char *canonical) {
  if (Moonbit_array_length(output) != OAS_MAX_INPUT + 1u) return -2;
  const char *root = (const char *)root_input;
  const char *relative = (const char *)relative_input;
  if (root[0] != '/' || !relative[0] || relative[0] == '/' ||
      strchr(relative, ':') || strchr(relative, '\\')) return -5;
  int descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (descriptor < 0) return -1;
  if (strcmp(root, "/") != 0) {
    char *parts = strdup(root + 1);
    if (!parts) { close(descriptor); return -2; }
    descriptor = oas_walk(descriptor, parts, 1);
    free(parts);
    if (descriptor < 0) return descriptor;
  }
  char *parts = strdup(relative);
  if (!parts) { close(descriptor); return -2; }
  descriptor = oas_walk(descriptor, parts, 0);
  free(parts);
  if (descriptor < 0) return descriptor;
  struct stat info;
  if (fstat(descriptor, &info) != 0) { close(descriptor); return -2; }
  if (!S_ISREG(info.st_mode)) { close(descriptor); return -3; }
  if (info.st_size > OAS_MAX_INPUT) { close(descriptor); return -4; }
  size_t root_length = strlen(root);
  size_t relative_length = strlen(relative);
  size_t slash = root_length && root[root_length - 1] == '/' ? 0u : 1u;
  if (root_length + slash + relative_length + 1u > (size_t)Moonbit_array_length(canonical)) {
    close(descriptor); return -2;
  }
  memcpy(canonical, root, root_length);
  if (slash) canonical[root_length] = '/';
  memcpy(canonical + root_length + slash, relative, relative_length + 1u);
  FILE *file = fdopen(descriptor, "rb");
  if (!file) { close(descriptor); return -2; }
  size_t length = fread(output, 1, OAS_MAX_INPUT + 1u, file);
  int failed = ferror(file);
  if (fclose(file) != 0) failed = 1;
  return failed ? -2 : (int32_t)length;
}
#endif
