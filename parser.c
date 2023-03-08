// TODO check if requested file is actually directory

#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_FILE_NAME 256
#define MAX_URI 512
#define MAX_STATUS_LEN 31
#define HTTP_VER_LEN 10
#define HTTP_METH_LEN 10
#define MAX_FILE_EXT 10
#define DIR "www"

// file types
#define HTML    0
#define PNG     1
#define GIF     2
#define JPG     3
#define ICO     4
#define CSS     5
#define JS      6
#define TXT     7
#define FILETYPE_CT 7



// HTTP status
#define OK      "200 OK"
#define BADREQ  "400 Bad Request"
#define FORBID  "403 Forbidden"
#define NOTFND  "404 Not Found"
#define BADMETH "405 Method Not Allowed"
#define BADHTTP "505 HTTP Version Not Supported"

struct f_metadata
{
    char f_name[MAX_FILE_NAME];
    FILE *f_ptr;
    int f_type;
    size_t f_size;
};

struct http_req
{
    char method[HTTP_METH_LEN];
    char uri[MAX_URI];
    char http_ver[HTTP_VER_LEN];
};

struct http_resp
{
    char http_ver[HTTP_VER_LEN];
    char status[MAX_STATUS_LEN];
    struct f_metadata * fmd_ptr;
};

int min(int a, int b)
{
    return a < b ? a : b;
}

// citation: https://stackoverflow.com/questions/4553012/checking-if-a-file-is-a-directory-or-just-a-file
int isFile(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

void clearReq(struct http_req *req)
{
    memset(req->method, 0, HTTP_METH_LEN);
    memset(req->uri, 0, MAX_URI);
    memset(req->http_ver, 0, HTTP_VER_LEN);
}

void clearResp(struct http_resp *resp)
{
    memset(resp->http_ver, 0, HTTP_VER_LEN);
    memset(resp->status, 0, MAX_STATUS_LEN);
    resp->fmd_ptr = NULL;
}

// TODO must free
int parseFile()
{

}

int getFileType(char *path)
{
    regex_t reg;
    regmatch_t reg_match;
    char match[MAX_FILE_EXT];

    if(regcomp(&reg, "\\.[a-zA-Z0-9]+$", REG_EXTENDED))
    {
        printf("Regex compilation failed.\n");
        return -1;
    }

    if(regexec(&reg, path, 1, &reg_match, 0) == REG_NOMATCH)
    {
        printf("No regex match found.\n");
        return -1;
    }

    // TODO think there might be a potential bug here
    memset(match, 0, MAX_FILE_EXT);
    strncpy(match, path + reg_match.rm_so, min(reg_match.rm_eo - reg_match.rm_so, MAX_FILE_EXT - 1));

    char hits[FILETYPE_CT][MAX_FILE_EXT] = {".html", ".png", ".gif", ".jpg", ".ico", ".css", ".js"};

    for(int i = 0; i < FILETYPE_CT; i++)
        if(!strcmp(match, hits[i]))
            return i;
}

int validateRequest(struct http_req *req, struct http_resp *resp)
{
    if(strcmp(req->method, "GET"))
    {
        strcpy(resp->status, BADMETH);
        return -1;
    }

    if(strcmp(req->http_ver, "HTTP/1.0") && strcmp(req->http_ver, "HTTP/1.1"))
    {
        strcpy(resp->status, BADHTTP);
        return -1;
    }

    char * adj_path = malloc(strlen(DIR) + strlen(req->uri));
    sprintf(adj_path, "%s%s", DIR, req->uri);

    // TODO kinda terrible, ensures that request is not a directory
    // should this be a different status?
    if(!isFile(adj_path))
    {
        strcpy(resp->status, NOTFND);
        return -1;
    }

    // TODO maybe regex for valid uri? marybe just try to open file. idk
    if(access(adj_path, R_OK))
    {
        switch(errno)
        {
            case EACCES:
                strcpy(resp->status, FORBID);
                break;

            default:
                strcpy(resp->status, NOTFND);
                break;
        }

        return -1;
    }

    strcpy(resp->status, OK);
    resp->fmd_ptr = malloc(sizeof(struct f_metadata));
    if(!(resp->fmd_ptr->f_ptr = fopen(adj_path, "r")))
    {
        printf("Failed to open file.\n");
        exit(-1);
    }
    
    //get file size
    fseek(resp->fmd_ptr->f_ptr, 0, SEEK_END);
    resp->fmd_ptr->f_size = ftell(resp->fmd_ptr->f_ptr);
    rewind(resp->fmd_ptr->f_ptr);

    // get file type
    resp->fmd_ptr->f_type = getFileType(req->uri);

    return 0;
}

int parseRequest(char * req_text, struct http_req * req)
{
    char *token;
    // why on earth does this segfault?
    // memset(&req, '\0', sizeof(req));
    clearReq(req);

    // extract method
    token = strtok(req_text, " ");
    if(token == NULL)
        return -1;

    strncpy(req->method, token, HTTP_METH_LEN - 1);

    // extract URI

    token = strtok(NULL, " ");
    if(token == NULL)
        return -1;

    strncpy(req->uri, token, MAX_URI - 1);

    token = strtok(NULL, "\r\n");
    if(token == NULL)
        return -1;

    strncpy(req->http_ver, token, HTTP_VER_LEN - 1);

    return 0;
}

int processRequest(char * req_text, struct http_resp  *resp)
{

    struct http_req req;
    clearReq(&req);

    // TODO is there any way to set this in struct definition?
    strcpy(resp->http_ver, "HTTP/1.1");

    if(parseRequest(req_text, &req))
    {
        // printf("failed to parse request.\n");
        strcpy(resp->status, BADREQ);
        return -1;
    }

    validateRequest(&req, resp);
}

int main()
{

    // if(chdir("www"))
    // {
    //     printf("failed to change dir:\n");
    //     exit(-1);
    // }

    // request in
    // break request into method, uri, http version
    // check validity of each segment, populating response as you go

    char request_text[10000];
    char *cursor = request_text;
    int bytes;

    FILE *fptr = fopen("req_example.txt", "r");

    while((bytes = fread(cursor, 1, 64, fptr)))
    {
        cursor += bytes;
    }

    printf("%s\n\n\n\n\n", request_text);

    struct http_resp resp;

    // while(1)
    // {
    //     fgets(request_text, 1000, stdin);

        clearResp(&resp);
        processRequest(request_text, &resp);

        printf("%s %s\r\n\r\n", resp.http_ver, resp.status);
    // }
}