#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <ctype.h>
#include <time.h>

#define MAX_PASSWORD_LENGTH 128
#define MAX_USERNAME_LENGTH 64
#define MAX_TITLE_LENGTH 64
#define MAX_WEBSITE_LENGTH 256
#define MAX_CATEGORY_LENGTH 32
#define MAX_PASSWORD_ENTRIES 2000

#define PASSWORD_ENTRIES_FILE "password_entries.dat"

typedef struct {
    int id;
    char title[MAX_TITLE_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char website[MAX_WEBSITE_LENGTH];
    char category[MAX_CATEGORY_LENGTH];
    char created_at[26];
} PasswordEntry;

PasswordEntry password_entries[MAX_PASSWORD_ENTRIES];
int password_entry_count = 0;

static void secure_clear_buffer(void* buffer, size_t length);
static bool read_secure_input(char* buffer, size_t max_length, bool hide_input);
static bool validate_system_credentials(const char* username, const char* password);
static char* generate_secure_password(unsigned int length, bool use_upper, bool use_lower, bool use_digits, bool use_special);
static bool add_password_entry(PasswordEntry* entry);
static bool view_password_entry(int entry_id);
static bool delete_password_entry(int entry_id);
static void reindex_password_entries();

void display_menu() {
    printf("\n=== CipherKeep Password Manager ===\n");
    printf("1. Generate New Password\n");
    printf("2. Add Password Entry\n");
    printf("3. View Password\n");
    printf("4. Delete Password Entry\n");
    printf("5. List All Passwords\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
    fflush(stdout);
}

int main() {
    char username[MAX_USERNAME_LENGTH] = {0};
    char password[MAX_PASSWORD_LENGTH] = {0};

    srand((unsigned int)(time(NULL) ^ (GetCurrentProcessId() << 16)));

    printf("=== Welcome to CipherKeep ===\n");
    printf("Enter your Windows username: ");
    if (!read_secure_input(username, MAX_USERNAME_LENGTH - 1, false)) {
        return 1;
    }

    printf("Enter your Windows password: ");
    if (!read_secure_input(password, MAX_PASSWORD_LENGTH - 1, true)) {
        secure_clear_buffer(password, MAX_PASSWORD_LENGTH);
        return 1;
    }

    if (!validate_system_credentials(username, password)) {
        printf("Authentication failed. Exiting.\n");
        secure_clear_buffer(password, MAX_PASSWORD_LENGTH);
        return 1;
    }

    printf("Authentication successful!\n");
    secure_clear_buffer(password, MAX_PASSWORD_LENGTH);


    FILE* file = fopen(PASSWORD_ENTRIES_FILE, "rb");
    if (file) {
        PasswordEntry entry;
        password_entry_count = 0;
        while (fread(&entry, sizeof(PasswordEntry), 1, file) == 1) {
            password_entries[password_entry_count++] = entry;
        }
        fclose(file);
    }

    int choice;
    char input_buffer[MAX_PASSWORD_LENGTH];
    bool running = true;

    while (running) {
        display_menu();
        if (!fgets(input_buffer, sizeof(input_buffer), stdin)) continue;
        choice = atoi(input_buffer);

        switch (choice) {
            case 1: {
                unsigned int length;
                bool use_upper = false, use_lower = false;
                bool use_digits = false, use_special = false;

                printf("Enter password length (12-128): ");
                if (!fgets(input_buffer, sizeof(input_buffer), stdin)) continue;
                length = (unsigned int)atoi(input_buffer);

                if (length < 12 || length > 128) length = 16;

                printf("Include uppercase letters? (y/n): ");
                use_upper = fgets(input_buffer, sizeof(input_buffer), stdin) && (input_buffer[0] == 'y' || input_buffer[0] == 'Y');
                printf("Include lowercase letters? (y/n): ");
                use_lower = fgets(input_buffer, sizeof(input_buffer), stdin) && (input_buffer[0] == 'y' || input_buffer[0] == 'Y');
                printf("Include digits? (y/n): ");
                use_digits = fgets(input_buffer, sizeof(input_buffer), stdin) && (input_buffer[0] == 'y' || input_buffer[0] == 'Y');
                printf("Include special characters? (y/n): ");
                use_special = fgets(input_buffer, sizeof(input_buffer), stdin) && (input_buffer[0] == 'y' || input_buffer[0] == 'Y');

                char* generated = generate_secure_password(length, use_upper, use_lower, use_digits, use_special);
                if (generated) {
                    printf("\nGenerated password: %s\n", generated);
                    secure_clear_buffer(generated, strlen(generated));
                    free(generated);
                }
                break;
            }

            case 2: {
                PasswordEntry entry = {0};

                printf("\nEnter title: ");
                if (!read_secure_input(entry.title, MAX_TITLE_LENGTH - 1, false)) continue;

                printf("Enter username: ");
                if (!read_secure_input(entry.username, MAX_USERNAME_LENGTH - 1, false)) continue;

                printf("Enter website URL: ");
                if (!read_secure_input(entry.website, MAX_WEBSITE_LENGTH - 1, false)) continue;

                printf("Enter category: ");
                if (!read_secure_input(entry.category, MAX_CATEGORY_LENGTH - 1, false)) continue;

                time_t now = time(NULL);
                strftime(entry.created_at, sizeof(entry.created_at), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

                if (add_password_entry(&entry)) printf("Password entry added successfully!\n");
                break;
            }

            case 3: {
                int entry_id;
                printf("\nEnter the password entry ID to view: ");
                if (!fgets(input_buffer, sizeof(input_buffer), stdin)) continue;
                entry_id = atoi(input_buffer);

                if (!view_password_entry(entry_id)) printf("Password entry with ID %d not found.\n", entry_id);
                break;
            }

            case 4: {
                int entry_id;
                printf("\nEnter the password entry ID to delete: ");
                if (!fgets(input_buffer, sizeof(input_buffer), stdin)) continue;
                entry_id = atoi(input_buffer);

                if (delete_password_entry(entry_id)) {
                    printf("Password entry with ID %d deleted successfully.\n", entry_id);
                } else {
                    printf("Password entry with ID %d not found.\n", entry_id);
                }
                break;
            }

            case 5: {
                printf("\n=== Password Entries ===\n");
                for (int i = 0; i < password_entry_count; i++) {
                    printf("ID: %d | Title: %s | Username: %s | Website: %s | Category: %s | Created: %s\n",
                           password_entries[i].id, password_entries[i].title,
                           password_entries[i].username, password_entries[i].website,
                           password_entries[i].category, password_entries[i].created_at);
                }
                break;
            }

            case 0:
                running = false;
                break;
        }

        secure_clear_buffer(input_buffer, sizeof(input_buffer));
    }


    file = fopen(PASSWORD_ENTRIES_FILE, "wb");
    if (file) {
        for (int i = 0; i < password_entry_count; i++) {
            fwrite(&password_entries[i], sizeof(PasswordEntry), 1, file);
        }
        fclose(file);
    }

    return 0;
}

static void secure_clear_buffer(void* buffer, size_t length) {
    if (buffer) {
        volatile unsigned char* p = buffer;
        while (length--) *p++ = 0;
    }
}

static bool read_secure_input(char* buffer, size_t max_length, bool hide_input) {
    if (!buffer || max_length == 0) return false;

    if (hide_input) {
        // Windows-specific method to hide password input
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

        if (!fgets(buffer, max_length + 1, stdin)) {
            SetConsoleMode(hStdin, mode);
            return false;
        }

        SetConsoleMode(hStdin, mode);


        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }

        printf("\n");
        return true;
    } else {
        if (!fgets(buffer, max_length + 1, stdin)) return false;


        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }

        return true;
    }
}

static bool validate_system_credentials(const char* username, const char* password) {
    HANDLE token;
    if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token)) {
        CloseHandle(token);
        return true;
    }

    printf("Invalid Windows credentials.\n");
    return false;
}

static char* generate_secure_password(unsigned int length, bool use_upper, bool use_lower, bool use_digits, bool use_special) {
    const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char lower[] = "abcdefghijklmnopqrstuvwxyz";
    const char digits[] = "0123456789";
    const char special[] = "!@#$%^&*()_-+=<>?";

    char* charset = calloc(MAX_PASSWORD_LENGTH, sizeof(char));
    if (!charset) return NULL;

    if (use_upper) strcat(charset, upper);
    if (use_lower) strcat(charset, lower);
    if (use_digits) strcat(charset, digits);
    if (use_special) strcat(charset, special);

    if (strlen(charset) == 0) {
        free(charset);
        return NULL;
    }

    char* password = calloc(length + 1, sizeof(char));
    if (!password) {
        free(charset);
        return NULL;
    }

    for (unsigned int i = 0; i < length; i++) {
        password[i] = charset[rand() % strlen(charset)];
    }

    free(charset);
    return password;
}

static bool add_password_entry(PasswordEntry* entry) {
    if (password_entry_count >= MAX_PASSWORD_ENTRIES) return false;

    entry->id = password_entry_count + 1;

    printf("Enter password: ");
    if (!read_secure_input(entry->password, MAX_PASSWORD_LENGTH - 1, true)) return false;

    password_entries[password_entry_count++] = *entry;


    FILE* file = fopen(PASSWORD_ENTRIES_FILE, "ab");
    if (!file) {
        printf("Error opening file for writing.\n");
        return false;
    }

    if (fwrite(entry, sizeof(PasswordEntry), 1, file) != 1) {
        printf("Error writing to file.\n");
        fclose(file);
        return false;
    }

    fclose(file);
    return true;
}

static bool view_password_entry(int entry_id) {

    FILE* file = fopen(PASSWORD_ENTRIES_FILE, "rb");
    if (!file) {
        printf("Error opening file for reading.\n");
        return false;
    }

    PasswordEntry entry;
    password_entry_count = 0;
    while (fread(&entry, sizeof(PasswordEntry), 1, file) == 1) {
        password_entries[password_entry_count++] = entry;
    }

    fclose(file);


    for (int i = 0; i < password_entry_count; i++) {
        if (password_entries[i].id == entry_id) {
            printf("\nTitle: %s\n", password_entries[i].title);
            printf("Username: %s\n", password_entries[i].username);
            printf("Website: %s\n", password_entries[i].website);
            printf("Category: %s\n", password_entries[i].category);
            printf("Password: %s\n", password_entries[i].password);
            printf("Created: %s\n", password_entries[i].created_at);
            return true;
        }
    }

    printf("Password entry with ID %d not found.\n", entry_id);
    return false;
}

static bool delete_password_entry(int entry_id) {

    FILE* file = fopen(PASSWORD_ENTRIES_FILE, "rb");
    if (!file) {
        printf("Error opening file for reading.\n");
        return false;
    }

    PasswordEntry entries[MAX_PASSWORD_ENTRIES];
    int count = 0;
    PasswordEntry entry;
    while (fread(&entry, sizeof(PasswordEntry), 1, file) == 1) {
        if (entry.id != entry_id) {
            entries[count++] = entry;
        }
    }
    fclose(file);

    if (count == password_entry_count) {
        return false;
    }

    // Reindex the entries
    for (int i = 0; i < count; i++) {
        entries[i].id = i + 1;
    }

    // Save the remaining entries back to the file
    file = fopen(PASSWORD_ENTRIES_FILE, "wb");
    if (!file) {
        printf("Error opening file for writing.\n");
        return false;
    }

    for (int i = 0; i < count; i++) {
        fwrite(&entries[i], sizeof(PasswordEntry), 1, file);
    }
    fclose(file);

    password_entry_count = count;
    memcpy(password_entries, entries, count * sizeof(PasswordEntry));

    return true;
}
