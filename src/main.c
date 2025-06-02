#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #define PATH_SEP '\\'
#else
    #include <dirent.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #define PATH_SEP '/'
#endif

#define BUFFER_SIZE 8192
#define MAX_PATH_LEN 256
#define MAX_FILES 256
#define MAX_PATTERN_LEN 32
#define MAX_PREFIX_LEN 64
#define MAX_GUARD_LEN 64

typedef enum output_format {
    FORMAT_HEX = 0,
    FORMAT_DEC,
    FORMAT_OCT
} output_format_t;

typedef struct config {
    char input_dir[MAX_PATH_LEN];
    char output_dir[MAX_PATH_LEN];
    char pattern[MAX_PATTERN_LEN];
    char prefix[MAX_PREFIX_LEN];
    char guard_prefix[MAX_GUARD_LEN];
    output_format_t format;
    int32_t bytes_per_line;
    bool include_size;
    bool verbose;
    bool uppercase;
} config_t;

void print_help(const char* program_name) {
    printf("bin2header - Convert binary files to C/C++ headers\n");
    printf("Usage: %s [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -i <dir>    Input directory (default: '.')\n");
    printf("  -o <dir>    Output directory (default: '.')\n");
    printf("  -p <ext>    File extension to match (default: '*')\n");
    printf("  -f <format> Output format (hex, dec, oct) (default: hex)\n");
    printf("  -b <num>    Bytes per line (default: 16)\n");
    printf("  -x <prefix> Variable name prefix (default: 'g_')\n");
    printf("  -g <prefix> Header guard prefix (default: 'GENERATED_')\n");
    printf("  -s          Include array size variable (default: yes)\n");
    printf("  -u          Use uppercase for hex values (default: no)\n");
    printf("  -v          Verbose output\n");
    printf("  -h          Show this help message\n");
    printf("Example:\n");
    printf("  %s -i assets -o include -p .bin -f hex -b 12 -x ASSET_ -v\n", program_name);
    printf("This tool converts any binary file into a C/C++ header containing\n");
    printf("the file's contents as an array. Useful for embedding assets,\n");
    printf("resources, or any binary data directly into your code.\n");
}

char* get_file_base_name(const char* path) {
    const char* last_sep = strrchr(path, PATH_SEP);
    const char* base = last_sep ? last_sep + 1 : path;
    static char result[MAX_PATH_LEN];
    strncpy(result, base, sizeof(result) - 1);
    char* dot = strrchr(result, '.');
    if (dot) *dot = '\0';
    return result;
}

void sanitize_identifier(char* str) {
    // First char must be a letter or underscore
    if (!isalpha((unsigned char)*str) && *str != '_') {
        memmove(str + 1, str, strlen(str) + 1);
        *str = '_';
    }

    // Replace invalid character with underscores
    for (char* p = str; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') {
            *p = '_';
        }
    }
}

void create_header_guard(const char* base_name, const char* prefix, char* guard, size_t guard_size) {
    snprintf(guard, guard_size, "%s%s_H", prefix, base_name);
    for (char* p = guard; *p; p++) {
        *p = (char)toupper((unsigned char)*p);
    }
}

void write_byte(FILE* output, unsigned char byte, output_format_t format, bool uppercase) {
    switch (format) {
        case FORMAT_HEX:
            fprintf(output, uppercase ? "0x%02X" : "0x%02x", byte);
            break;
        case FORMAT_DEC:
            fprintf(output, "%u", byte);
            break;
        case FORMAT_OCT:
            fprintf(output, "0%03o", byte);
            break;
    }
}

void init_config(config_t* config) {
    strncpy(config->input_dir, ".", sizeof(config->input_dir) - 1);
    strncpy(config->output_dir, ".", sizeof(config->output_dir) - 1);
    strncpy(config->pattern, "*", sizeof(config->pattern) - 1);
    strncpy(config->prefix, "g_", sizeof(config->prefix) - 1);
    strncpy(config->guard_prefix, "GENERATED_", sizeof(config->guard_prefix) - 1);
    config->format = FORMAT_HEX;
    config->bytes_per_line = 16;
    config->include_size = true;
    config->verbose = false;
    config->uppercase = false;
}

bool parse_args(int argc, char* argv[], config_t* config) {
    init_config(config);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return false;
        }
        else if (strcmp(argv[i], "-v") == 0) {
            config->verbose = true;
        }
        else if (strcmp(argv[i], "-s") == 0) {
            // TODO: is this really what I want?
            config->include_size = false;
        }
        else if (strcmp(argv[i], "-u") == 0) {
            config->uppercase = true;
        }
        else if (i + 1 < argc) {
            if (strcmp(argv[i], "-i") == 0) {
                strncpy(config->input_dir, argv[++i], sizeof(config->input_dir) - 1);
            }
            else if (strcmp(argv[i], "-o") == 0) {
                strncpy(config->output_dir, argv[++i], sizeof(config->output_dir) - 1);
            }
            else if (strcmp(argv[i], "-p") == 0) {
                strncpy(config->pattern, argv[++i], sizeof(config->pattern) - 1);
            }
            else if (strcmp(argv[i], "-x") == 0) {
                strncpy(config->prefix, argv[++i], sizeof(config->prefix) - 1);
            }
            else if (strcmp(argv[i], "-g") == 0) {
                strncpy(config->guard_prefix, argv[++i], sizeof(config->guard_prefix) - 1);
            }
            else if (strcmp(argv[i], "-f") == 0) {
                const char* format = argv[++i];
                
                if (strcmp(format, "hex") == 0) config->format = FORMAT_HEX;
                else if (strcmp(format, "dec") == 0) config->format = FORMAT_DEC;
                else if (strcmp(format, "oct") == 0) config->format = FORMAT_OCT;
                else {
                    fprintf(stderr, "Invalid format: %s\n", format);
                    return false;
                }
            }
            else if (strcmp(argv[i], "-b") == 0) {
                config->bytes_per_line = atoi(argv[++i]);
                if (config->bytes_per_line < 1) {
                    fprintf(stderr, "Invalid bytes per line: %d\n", config->bytes_per_line);
                    return false;
                }
            }
            else {
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                print_help(argv[0]);
                return false;
            }
        }
    }

    return true;
}

void ensure_dir(const char* path) {
#if defined(_WIN32)
    CreateDirectoryA(path, NULL);
#else
    mkdir(path, 0755);
#endif
}

bool list_files(const char* dir_path, const char* pattern, char files[][MAX_PATH_LEN], int* count) {
#if defined(_WIN32)
    char search_path[MAX_PATH_LEN];
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    snprintf(search_path, sizeof(search_path), "%s\\*%s", dir_path, pattern);

    find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return false;

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            snprintf(files[*count], MAX_PATH_LEN, "%s\\%s", dir_path, find_data.cFileName);
            (*count)++;
        }
    } while (*count < MAX_FILES && FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return true;
#else
    DIR* dir = opendir(dir_path);
    if (!dir) return false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && *count < MAX_FILES) {
        if (entry->d_type == DT_REG &&
            (strcmp(pattern, "*") == 0 || strstr(entry->d_name, pattern))) {
            snprintf(files[*count], MAX_PATH_LEN, "%s/%s", dir_path, entry->d_name);
            (*count)++;
        }
    }

    closedir(dir);
    return true;
#endif
}

bool convert_to_header(const char* input_path, const char* output_dir, const config_t* config) {
    FILE* input = fopen(input_path, "rb");
    if (!input) {
        fprintf(stderr, "Error: Cannot open input file %s: %s\n",
                input_path, strerror(errno));
        
        return false;
    }

    // Get file size
    fseek(input, 0, SEEK_END);
    size_t file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    // Create variable name from filename
    char* base_name = get_file_base_name(input_path);
    sanitize_identifier(base_name);

    // Create header guard
    char guard[MAX_GUARD_LEN];
    create_header_guard(base_name, config->guard_prefix, guard, sizeof(guard));

    // Create output path
    char output_path[MAX_PATH_LEN];
    snprintf(output_path, sizeof(output_path), "%s%c%s.h",
            output_dir, PATH_SEP, base_name);

    FILE* output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "Error: Cannot create output file %s: %s\n",
                output_path, strerror(errno));
        fclose(input);
        return false;
    }

    if (config->verbose) {
        printf("Converting %s to %s\n", input_path, output_path);
    }

    // Write header
    fprintf(output, "#ifndef %s\n", guard);
    fprintf(output, "#define %s\n\n", guard);

    // Write array declaration
    fprintf(output, "static const unsigned char %s%s[] = {",
            config->prefix, base_name);

    // Write data
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t total_bytes = 0;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            if (total_bytes % config->bytes_per_line == 0) {
                fprintf(output, "\n    ");
            }
            write_byte(output, buffer[i], config->format, config->uppercase);
            if (total_bytes < file_size - 1) {
                fprintf(output, ",");
                if (total_bytes % config->bytes_per_line != config->bytes_per_line - 1) {
                    fprintf(output, " ");
                }
            }
            total_bytes++;
        }
    }

    fprintf(output, "\n};\n\n");

    // Write size variable if needed
    if (config->include_size) {
        fprintf(output, "static const unsigned long long %s%s_size = sizeof(%s%s);\n\n",
                config->prefix, base_name, config->prefix, base_name);
    }

    fprintf(output, "#endif /* %s */\n", guard);

    fclose(input);
    fclose(output);

    return true;
}

int main(int argc, char* argv[]) {
    config_t config = {0};
    if (!parse_args(argc, argv, &config)) {
        return 1;
    }
    
    // Make sure output dir exists
    ensure_dir(config.output_dir);

    // List files
    char files[MAX_FILES][MAX_PATH_LEN];
    int32_t file_count = 0;

    if (!list_files(config.input_dir, config.pattern, files, &file_count)) {
        fprintf(stderr, "Error reading directory: %s\n", config.input_dir);
        return 1;
    }

    if (file_count == 0) {
        fprintf(stderr, "No matching files found in %s\n", config.input_dir);
        return 1;
    }

    // Process each file
    int32_t success_count = 0;
    for (int32_t i = 0; i < file_count; i++) {
        if (convert_to_header(files[i], config.output_dir, &config)) {
            success_count++;
        }
    }

    if (config.verbose) {
        printf("Processed %d files successfully out of %d total\n", success_count, file_count);
    }

    return success_count == file_count ? 0 : 1;
}
