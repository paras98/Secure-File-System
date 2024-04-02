#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <sodium.h>
#define MAX_LINE_LENGTH 1024
#define BLOWFISH_KEY_SIZE 16

// Structure to represent a file node
struct FileNode {
    char filename[MAX_LINE_LENGTH];
    char content[MAX_LINE_LENGTH];
    struct FileNode* next;
};

// Structure to represent a user node
struct UserNode {
    char username[MAX_LINE_LENGTH];
    char key[2 * SHA256_DIGEST_LENGTH + 1]; 
    unsigned char nonce[crypto_secretbox_NONCEBYTES]; // New field for nonce
    struct FileNode* files;
    struct UserNode* next;
};

// Linked list head for users
struct UserNode* userList = NULL;

// Function to URL encode a string
char* escapeString(const char* input) {
    size_t len = strlen(input);
    char* encodedString = (char*)malloc((3 * len) + 1);  // Allocate enough space for worst-case scenario

    if (encodedString == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }

    size_t encodedIndex = 0;

    for (size_t i = 0; i < len; i++) {
        if ((input[i] >= 'A' && input[i] <= 'Z') ||
            (input[i] >= 'a' && input[i] <= 'z') ||
            (input[i] >= '0' && input[i] <= '9') ||
            input[i] == '-' || input[i] == '_' || input[i] == '.' || input[i] == '~') {
            // Characters in the unreserved set, as per RFC 3986
            encodedString[encodedIndex++] = input[i];
        } else {
            // Percent-encode other characters
            encodedIndex += snprintf(encodedString + encodedIndex, 4, "%%%02X", input[i]);
        }
    }

    encodedString[encodedIndex] = '\0';  // Null-terminate the encoded string
    return encodedString;
}

// Function to URL decode a string
char* unescapeString(const char* input) {
    size_t len = strlen(input);
    char* decodedString = (char*)malloc(len + 1);  // Allocate enough space

    if (decodedString == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }

    size_t decodedIndex = 0;

    for (size_t i = 0; i < len; i++) {
        if (input[i] == '%' && i + 2 < len && isxdigit(input[i + 1]) && isxdigit(input[i + 2])) {
            // Percent-encoded sequence found
            sscanf(input + i + 1, "%02X", (unsigned int*)(decodedString + decodedIndex));
            i += 2;
            decodedIndex++;
        } else if (input[i] == '+') {
            // Replace '+' with space
            decodedString[decodedIndex++] = ' ';
        } else {
            // Copy the character as is to the decoded string
            decodedString[decodedIndex++] = input[i];
        }
    }

    decodedString[decodedIndex] = '\0';  // Null-terminate the decoded string
    return decodedString;
}

// Function to extract the value of a key from a line in JSON format
void extractValue(const char* line, const char* key, char* value, size_t max_length) {
    const char* start = strstr(line, key);
    if (start) {
        start = start + strlen(key) + 3;  // Skip key, colon, double quote

        const char* end = strchr(start, '"');
        if (end) {
            size_t length = (size_t)(end - start);
            length = length < max_length - 1 ? length : max_length - 1;
            strncpy(value, start, length);
            value[length] = '\0';
        }
    }
}

// Function to extract files from the given text and append to the user's files
void extractAndAppendFiles(struct UserNode* user, const char* text) {
    // Find the position of "files" in the text
    const char* filesStart = strstr(text, "\"files\": [");
    if (!filesStart) {
        printf("No files found\n");
        return;
    }

    // Move to the position after "files": [
    filesStart += strlen("\"files\": [");

    // Find the position of "]}"
    const char* filesEnd = strstr(filesStart, "]}");
    if (!filesEnd) {
        printf("Invalid format\n");
        return;
    }

    // Copy the content between "files": [ and ]}
    char filesText[MAX_LINE_LENGTH];
    size_t length = filesEnd - filesStart;
    length = length < sizeof(filesText) - 1 ? length : sizeof(filesText) - 1;
    strncpy(filesText, filesStart, length);
    filesText[length] = '\0';

    // Process each file within "files": [ and ]}
    char* fileToken = strtok(filesText, "{},");
    while (fileToken != NULL) {
        // Extract filename and content
        char filename[MAX_LINE_LENGTH];
        char content[MAX_LINE_LENGTH];
        sscanf(fileToken, "\"%[^\"]\":\"%[^\"]\"", filename, content);
        char* unescapeFilename = unescapeString(filename);
        //char* unescapeContent = unescapeString(content);

        // Append the extracted file to the user's files
        struct FileNode* newFile = (struct FileNode*)malloc(sizeof(struct FileNode));
        strncpy(newFile->filename, unescapeFilename, sizeof(unescapeFilename) + 1);
        strncpy(newFile->content, content, sizeof(newFile->content));
        memset(content, '\0', sizeof(content));
        newFile->next = user->files;
        user->files = newFile;
        free(unescapeFilename);
        // Move to the next file token
        fileToken = strtok(NULL, "{},");
    }
}

// Function to read existing data from enc.db file into linked list
void readDataFromFile() {
    FILE* encDb = fopen("enc.db", "r");
    if (!encDb) {
        return;
    }

    char line[MAX_LINE_LENGTH];

    while (fgets(line, MAX_LINE_LENGTH, encDb) != NULL) {
        //printf("the line is %s",line);
        char extractedUsername[MAX_LINE_LENGTH];
        char extractedKey[MAX_LINE_LENGTH];
        char extractedNonce[2 * crypto_secretbox_NONCEBYTES + 1];

        // Extract username and key
        extractValue(line, "\"username\"", extractedUsername, sizeof(extractedUsername));
        extractValue(line, "\"key\"", extractedKey, sizeof(extractedKey));
        extractValue(line, "\"nonce\"", extractedNonce, sizeof(extractedNonce));
        //char* unencodeNonce = unescapeString(extractedNonce);
        struct UserNode* currentUser = userList;
        struct UserNode* prevUser = NULL;

        // Search for the user in the linked list
        while (currentUser != NULL) {
            if (strcmp(currentUser->username, extractedUsername) == 0 && strcmp(currentUser->key, extractedKey) == 0) {
                break;
            }
            prevUser = currentUser;
            currentUser = currentUser->next;
        }

        // If the user is not found, create a new user node
        if (currentUser == NULL) {
            currentUser = (struct UserNode*)malloc(sizeof(struct UserNode));
            strncpy(currentUser->username, extractedUsername, sizeof(currentUser->username));
            strncpy(currentUser->key, extractedKey, sizeof(currentUser->key));
            sodium_hex2bin(currentUser->nonce, sizeof(currentUser->nonce), extractedNonce, strlen(extractedNonce), NULL, NULL, NULL);
            //free(unencodeNonce);
            currentUser->files = NULL;
            currentUser->next = NULL;

            // Insert the new user node into the linked list
            if (prevUser == NULL) {
                // If the list is empty, set userList to the new user
                userList = currentUser;
            } else {
                // Otherwise, append the new user at the end of the list
                prevUser->next = currentUser;
            }
        }
        extractAndAppendFiles(currentUser,line);
    }

    fclose(encDb);
}


// Function to write updated data back to enc.db file
void writeDataToFile() {
    FILE* encDb = fopen("enc.db", "w");
    if (!encDb) {
        printf("Error opening enc.db for writing\n");
        exit(255);
    }

    struct UserNode* currentUser = userList;

    // Iterate through the linked list and write each node to the file
    while (currentUser != NULL) {
        char hexNonce[2 * crypto_secretbox_NONCEBYTES + 1];
        sodium_bin2hex(hexNonce, sizeof(hexNonce), currentUser->nonce, sizeof(currentUser->nonce));
        //printf("nonce is %s \n",hexNonce);
        //char* encodeNonce = escapeString(currentUser->nonce);
        fprintf(encDb, "{\"username\": \"%s\",\"key\": \"%s\",\"nonce\": \"%s\",\"files\": [",
                currentUser->username, currentUser->key, hexNonce);
        //free(encodeNonce);
        struct FileNode* currentFile = currentUser->files;
        while (currentFile != NULL) {
            // Escape special characters in filename and content before writing
            //printf("the cur fname %s and the cur cont %s \n",currentFile->filename, currentFile->content);
            char* escapedFilename = escapeString(currentFile->filename);
            // if(currentFile->content == NULL || currentFile->content == '\0')
            //char* escapedContent = escapeString(currentFile->content);
            //printf("the escapedFilename is %s escapedContent is %s \n",escapedFilename,escapedContent);
            fprintf(encDb, "{\"%s\":\"%s\"}%s",
                    escapedFilename, currentFile->content,
                    currentFile->next ? "," : "");
            // Free the memory allocated for escaped strings
            free(escapedFilename);
            //free(escapedContent);
            currentFile = currentFile->next;
        }

        fprintf(encDb, "]}%s\n", currentUser->next ? "," : "");

        currentUser = currentUser->next;
    }

    fclose(encDb);
}

// Function to free allocated memory for the linked list
void freeUserList() {
    struct UserNode* currentUser = userList;

    // Iterate through the linked list and free each node and its files
    while (currentUser != NULL) {
        struct FileNode* currentFile = currentUser->files;
        while (currentFile != NULL) {
            struct FileNode* nextFile = currentFile->next;
            free(currentFile);
            currentFile = nextFile;
        }

        struct UserNode* nextUser = currentUser->next;
        free(currentUser);
        currentUser = nextUser;
    }
}

// Function to check if a user is registered
int isUserRegistered(char* username, char* key) {
    struct UserNode* current = userList;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0 && strcmp(current->key, key) == 0) {
            return 1;  // User is registered
        }
        current = current->next;
    }
    return 0;  // User is not registered
}

int registerUserwithoutHash(char* username,char* key){
    // Hash the key using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)key, strlen(key), hash);

    // Convert the hash to a hexadecimal string
    char hashedKey[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashedKey + 2 * i, "%02x", hash[i]);
    }
    hashedKey[2 * SHA256_DIGEST_LENGTH] = '\0';
    int retVal = isUserRegistered(username,hashedKey);
    return(retVal);

}
void win(){
    printf("WIN WIN \n");
}
// Function to check if a user is registered
int isUserNameRegistered(char* username) {
    struct UserNode* current = userList;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            return 1;  // User is registered
        }
        current = current->next;
    }
    return 0;  // User is not registered
}
// Function to register a new user
int registerUser(char* username, char* key) {
    // if (isUserNameRegistered(username)) {
    //     printf("invalid\n");
    //     return 0;
    // }
     // Hash the key using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)key, strlen(key), hash);

    // Convert the hash to a hexadecimal string
    char hashedKey[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashedKey + 2 * i, "%02x", hash[i]);
    }
    hashedKey[2 * SHA256_DIGEST_LENGTH] = '\0';

    if (isUserRegistered(username, hashedKey)) {
        printf("User already registered\n");
        return 0;
    }
    if (isUserNameRegistered(username)) {
        printf("invalid\n");
        return 0;
    }
    // Create a new user node
    struct UserNode* currentUser = (struct UserNode*)malloc(sizeof(struct UserNode));
    strncpy(currentUser->username, username, sizeof(currentUser->username));
    strncpy(currentUser->key, hashedKey, sizeof(currentUser->key));
    currentUser->files = NULL;
    currentUser->next = NULL;

    // Generate a new nonce for the user
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes(nonce, sizeof(nonce));
    memcpy(currentUser->nonce, nonce, sizeof(currentUser->nonce));

    // Insert the new user node into the linked list
    struct UserNode* prevUser = NULL;
    struct UserNode* existingUser = userList;
    while (existingUser != NULL) {
                prevUser = existingUser;
        existingUser = existingUser->next;
    }

    if (prevUser == NULL) {
        userList = currentUser;
    } else {
        prevUser->next = currentUser;
    }
    printf("User '%s' has been registered\n",username);
    return 1;
}

// Function to check if a file exists for a user
int fileExists(char* username, char* filename) {
    struct UserNode* current = userList;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            struct FileNode* currentFile = current->files;
            while (currentFile != NULL) {
                if (strcmp(currentFile->filename, filename) == 0) {
                    return 1;  // File exists
                }
                currentFile = currentFile->next;
            }
        }
        current = current->next;
    }
    return 0;  // File does not exist
}

// Function to create a new file for a user
int createFile(char* username, char* filename) {
    struct UserNode* currentUser = userList;

    // Search for the user in the linked list
    while (currentUser != NULL) {
        if (strcmp(currentUser->username, username) == 0) {
            struct FileNode* currentFile = currentUser->files;

            // Check if the file already exists
            while (currentFile != NULL) {
                if (strcmp(currentFile->filename, filename) == 0) {
                    printf("invalid\n");
                    return 0;
                }
                currentFile = currentFile->next;
            }

            // Create a new file node
            struct FileNode* newFile = (struct FileNode*)malloc(sizeof(struct FileNode));
            strncpy(newFile->filename, filename, sizeof(newFile->filename));
            newFile->content[0] = '\0';  // Initialize content to an empty string
            newFile->next = currentUser->files;
            currentUser->files = newFile;
            printf("File '%s' has been created for user '%s'\n",filename,username);
            //printf("File created successfully\n");
            return 1;
        }
        currentUser = currentUser->next;
    }

    printf("invalid\n");
    return 0;
}

void extractReadableCharacters(const char *input, char *output) {
    while (*input) {
        if (isprint(*input)) {
            *output = *input;
            output++;
        }
        input++;
    }
    *output = '\0';  // Null-terminate the output string
}

void removeQuotes(char *str) {
    // Check if the string has at least two characters and starts with a double quote
    if (strlen(str) >= 2 && str[0] == '"' && str[strlen(str) - 1] == '"') {
        // Remove the leading double quote
        memmove(str, str + 1, strlen(str));

        // Remove the trailing double quote
        str[strlen(str) - 1] = '\0';
    }
}
int readFile1(char* content1, char* key, char* tgatbuff, char* nonce) {
    // Convert hex string to binary
    unsigned char ciphertext[strlen(content1) / 2];
    if (sodium_hex2bin(ciphertext, sizeof(ciphertext), content1, strlen(content1), NULL, NULL, NULL) < 0) {
        // Conversion error
        return 0;
    }

    // Decrypt the content
    size_t ciphertext_len = strlen(content1) / 2 - crypto_secretbox_MACBYTES;
    unsigned char decrypted[ciphertext_len];
    if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, key) != 0) {
        // Decryption failed
        return 0;
    }

    // Extract length and copy content into tgatbuff
    size_t contentLength;
    sscanf(decrypted, "%04zu|", &contentLength);
    memcpy(tgatbuff, decrypted + 5, contentLength);
    tgatbuff[contentLength] = '\0';

    return 1;
}

// Function to read from a file for a user with libsodium decryption
int readFile(char* username, char* filename) {
    struct UserNode* currentUser = userList;

    // Search for the user in the linked list
    while (currentUser != NULL) {
        if (strcmp(currentUser->username, username) == 0) {
            struct FileNode* currentFile = currentUser->files;

            // Search for the file in the user's files linked list
            while (currentFile != NULL) {
                if (strcmp(currentFile->filename, filename) == 0) {
                    // Convert hex string to binary
                    unsigned char ciphertext[strlen(currentFile->content) / 2];
                    if (sodium_hex2bin(ciphertext, sizeof(ciphertext), currentFile->content, strlen(currentFile->content), NULL, NULL, NULL) < 0) {
                        // Conversion error
                        return 0;
                    }

                    // Decrypt the content
                    size_t ciphertext_len = strlen(currentFile->content) / 2 - crypto_secretbox_MACBYTES;
                    unsigned char decrypted[ciphertext_len];
                    memset(decrypted, 0, sizeof(decrypted));
                    if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), (unsigned char*)currentUser->nonce, (unsigned char*)currentUser->key) != 0) {
                        // Decryption failed
                        return 0;
                    }

                    // Extract length and content from decrypted data
                    size_t contentLength;
                    sscanf(decrypted, "%04zu|", &contentLength);
                    char content[contentLength + 1];
                    memcpy(content, decrypted + 5, contentLength);
                    content[contentLength] = '\0';

                    printf("Content Length: %zu\n", contentLength);
                    printf("Content: %s\n", content);

                    return 1;
                }
                currentFile = currentFile->next;
            }

            // printf("File does not exist\n");
            return 0;
        }
        currentUser = currentUser->next;
    }

    printf("User not registered\n");
    return 0;
}

void copyUntilNewline(const char *source, char *destination) {
    while (*source && *source != '\0') {
        *destination = *source;
        source++;
        destination++;
    }
    *destination = '\0';  // Null-terminate the destination buffer
}

// Function to write to a file for a user with libsodium encryption
void writeFile(char* username, char* filename, char* content) {
    removeQuotes(content);
    //printf("The content is %s",content);
    struct UserNode* currentUser = userList;

    // Search for the user in the linked list
    while (currentUser != NULL) {
        if (strcmp(currentUser->username, username) == 0) {
            struct FileNode* currentFile = currentUser->files;

            // Search for the file in the user's files linked list
            while (currentFile != NULL) {
                if (strcmp(currentFile->filename, filename) == 0) {
                    unsigned char decrypted1[MAX_LINE_LENGTH];
                    memset(decrypted1, 0, sizeof(decrypted1));
                    if (strncmp(currentFile->content, "\0", 1) != 0 ) {
                        readFile1(currentFile->content, currentUser->key, decrypted1,currentUser->nonce);
                        // readFile(username, filename);
                        strcat(decrypted1, content);
                        // printf("this the contact string %s \n",decrypted1);
                        copyUntilNewline(decrypted1, content);
                        // printf("the new content is %s \n",content);
                    }
                    
                    // Combine length and content with '|'
                    char combinedContent[MAX_LINE_LENGTH + 10]; // Assuming a reasonable max length
                    snprintf(combinedContent, sizeof(combinedContent), "%04zu|%s", strlen(content), content);

                    // Encrypt the combined content
                    unsigned char ciphertext[strlen(combinedContent) + crypto_secretbox_MACBYTES];
                    crypto_secretbox_easy(ciphertext, (unsigned char*)combinedContent, strlen(combinedContent), (unsigned char*)currentUser->nonce, (unsigned char*)currentUser->key);

                    // Convert the ciphertext to hexadecimal string and store in the file
                    char hexCiphertext[2 * (strlen(combinedContent) + crypto_secretbox_MACBYTES) + 1];
                    sodium_bin2hex(hexCiphertext, sizeof(hexCiphertext), ciphertext, sizeof(ciphertext));

                    // Update file content
                    snprintf(currentFile->content, sizeof(currentFile->content), "%s", hexCiphertext);

                    printf("Data written to file '%s' by user '%s'\n", filename, username);
                    return;
                }
                currentFile = currentFile->next;
            }

            // printf("File does not exist\n");
            return;
        }
        currentUser = currentUser->next;
    }

    printf("User not registered\n");
}



// Entry point of the program
int main(int argc, char* argv[]) {
    // Read existing data from enc.db into linked list
    readDataFromFile();

    // Check the number of arguments
    if (argc < 3) {
        printf("invalid\n");
        freeUserList();
        return 255;
    }

    // Parse command-line arguments
    char* username = NULL;
    char* key = NULL;
    char* filename = NULL;
    char* content = NULL;
    int ucount = 0;
    int kcount = 0;
    int create_count = 0;
    int reg_count = 0;
    int fcount = 0;
    for (int i = 1; i < argc; i++) {
        switch (argv[i][0]) {
            case '-':
                switch (argv[i][1]) {
                    case 'u':
                        if(ucount>0){
                            printf("U more then 1 \n");
                            return 255;
                        }
                        username = argv[++i];
                        ucount++;
                        break;
                    case 'k':
                        if(kcount>0){
                            printf("K more then 1 \n");
                            return 255;
                        }
                        key = argv[++i];
                        kcount++;
                        break;
                    case 'f':
                        if(fcount>0){
                            printf("F more then 1 \n");
                            freeUserList();
                            return 255;
                        }
                        filename = argv[++i];
                        //printf("the file name is %s %d", filename,strcmp(filename,"read"));
                        if(filename == NULL || strcmp(filename,"read") == 0 || filename[0] == '-'){
                            printf("invalid");
                            freeUserList();
                            return 255;
                        }
                        fcount++;
                        break;
                    // case 't':
                    //     content = argv[++i];
                    //     break;
                    default:
                        printf("invalid\n");
                        freeUserList();
                        return 255;
                }
                break;
            case 'r':
                if (strcmp(argv[i], "register") == 0) {
                    if(reg_count>0){
                            freeUserList();
                            return 255;
                        }
                    if (username != NULL && key != NULL) {
                        int status = registerUser(username, key);
                        if( status == 0){
                            freeUserList();
                            return 255;
                        }
                        writeDataToFile();
                        reg_count++;
                    } else {
                        printf("invalid\n");
                        freeUserList();
                        return 255;
                    }
                } else if (strcmp(argv[i], "read") == 0) {
                    if (username != NULL && key != NULL && filename != NULL) {
                        if(registerUserwithoutHash(username, key)){
                            int status = readFile(username, filename);
                            if(status == 0){
                                printf("invalid\n");
                                freeUserList();
                                return 255;
                            }
                        }
                        else{
                            printf("invalid\n");
                            freeUserList();
                            return 255;
                        }
                    }
                    else {
                        printf("invalid\n");
                        freeUserList();
                        return 255;
                    }
                }
                break;
            case 'c':
                if (strcmp(argv[i], "create") == 0) {
                    if(create_count>0){
                            return 255;
                    }
                    if (username != NULL && filename != NULL) {
                        int status = createFile(username, filename);
                        if(status == 0){
                            freeUserList();
                            return 255;
                        }
                        writeDataToFile();
                        create_count++;
                    } else {
                        printf("invalid\n");
                        freeUserList();
                        return 255;
                    }
                }
                break;
            case 'w':
                if (strcmp(argv[i], "write") == 0) {
                    //printf("The content is %s \n",argv[i+1]);
                    content = argv[i+1];
                    if (username != NULL && key != NULL && filename != NULL && content != NULL) {
                        if(registerUserwithoutHash(username, key)){
                            writeFile(username, filename, content);
                            writeDataToFile();
                            // Free allocated memory
                            freeUserList();
                            return 0;                        
                        }
                        else {
                            printf("invalid\n");
                        freeUserList();
                        return 255;
                    }                        
                    } else {
                        printf("invalid\n");
                        freeUserList();
                        return 255;
                    }
                }
                break;
            default:
                printf("invalid\n");
                freeUserList();
                return 255;
        }
    }

    // Write the updated data back to enc.db

    // Free allocated memory
    freeUserList();

    return 0;
}