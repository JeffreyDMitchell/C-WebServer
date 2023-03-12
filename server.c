/* 
    TODO
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_QUEUED_CONNECTIONS 3
#define MAX_REQ_LEN 8192
#define MAX_FILE_NAME 256
#define MAX_URI 512
#define MAX_STATUS_LEN 31
#define HTTP_VER_LEN 10
#define HTTP_METH_LEN 10
#define MAX_FILE_EXT 10
#define SEND_BUF_SIZE 1024
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

struct netinfo
{
    struct sockaddr_in sin;
    socklen_t addr_len;
};

// citation: http://www.microhowto.info/howto/reap_zombie_processes_using_a_sigchld_handler.html
void handleSIGCHLD(int sig) 
{
    int saved_errno = errno;
    while (waitpid((pid_t)(-1), 0, WNOHANG) > 0);
    errno = saved_errno;
}

void handleSIGINT(int sig) 
{
    printf("Closing connections...\n");
    int saved_errno = errno;
    while (waitpid((pid_t)(-1), 0, WNOHANG) > 0);
    errno = saved_errno;
    printf("Connections closed.\n");
    exit(0);
}

int min(int a, int b)
{
    return a < b ? a : b;
}

// Beej's sendall function. mostly.
// citation https://beej.us/guide/bgnet/html/
int sendAll(int s, char *buf, int len)
{
    int total = 0;        
    int bytesleft = len; 
    int n;

    while(bytesleft) 
    {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) return -1;
        total += n;
        bytesleft -= n;
    }

    return total;
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

char * contentTypeString(int cont_type)
{
    // 23 is the longest string in the list
    static char hits[FILETYPE_CT][23] = {"text/html", "image/png", "image/gif", "image/jpg", "image/x-icon", "text/css", "application/javascript"};

    return hits[cont_type];
}

void destroyFMD(struct f_metadata * fmd)
{
    fclose(fmd->f_ptr);
    free(fmd);
}

int getFileType(char *path)
{
    regex_t reg;
    regmatch_t reg_match;
    char match[MAX_FILE_EXT];

    
    if(regcomp(&reg, "\\.[a-zA-Z0-9]+$", REG_EXTENDED))
    {
        printf("Regex compilation failed. (determine filetype)\n");
        exit(-1);
    }
    
    // in the event no determination could be made, treat it as text.
    if(regexec(&reg, path, 1, &reg_match, 0) == REG_NOMATCH)
    {
        printf("No regex match found.\n");
        return TXT;
    }

    memset(match, 0, MAX_FILE_EXT);
    strncpy(match, path + reg_match.rm_so, min(reg_match.rm_eo - reg_match.rm_so, MAX_FILE_EXT - 1));

    char hits[FILETYPE_CT][MAX_FILE_EXT] = {".html", ".png", ".gif", ".jpg", ".ico", ".css", ".js"};

    for(int i = 0; i < FILETYPE_CT; i++)
        if(!strcmp(match, hits[i]))
            return i;
}

int validateRequest(struct http_req *req, struct http_resp *resp)
{
    if(strcmp(req->http_ver, "HTTP/1.0") && strcmp(req->http_ver, "HTTP/1.1"))
    {
        strcpy(resp->status, BADHTTP);
        return -1;
    }

    // valid http version, aim to match
    strcpy(resp->http_ver, req->http_ver);

    if(strcmp(req->method, "GET"))
    {
        strcpy(resp->status, BADMETH);
        return -1;
    }

    char * adj_path = malloc(strlen(DIR) + strlen(req->uri));
    sprintf(adj_path, "%s%s", DIR, req->uri);

    if(!isFile(adj_path))
    {
        // request was for a directory, look for index.htm(l)
        // this is janky and ugly :)

        // making room for addition of index.htm(l), up to 10 characters
        int len = strlen(adj_path);
        if(!realloc(adj_path, len + 10))
        {
            printf("realloc failure\n");
            exit(-1);
        }

        // checking index.html
        strcpy(adj_path + len, "index.html");
        if(access(adj_path, F_OK))
        {
            // checking index.html
            strcpy(adj_path + len, "index.htm");
            if(access(adj_path, F_OK))
            {
                strcpy(resp->status, NOTFND);
                return -1;
            }
        }
    }

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
    resp->fmd_ptr->f_type = getFileType(adj_path);

    // path no longer needed, can be freed
    free(adj_path);

    return 0;
}

int parseRequest(char * req_text, struct http_req * req)
{
    regex_t reg;
    regmatch_t reg_match;
    char match[MAX_FILE_EXT];
    char * token;

    clearReq(req);
    
    if(regcomp(&reg, "^[A-Z]+ (/[^/ ]*)+ HTTP/[0-9]+\\.[0-9]+$", REG_EXTENDED))
    {
        printf("Regex compilation failed. (parse request)\n");
        return -1;
    }

    // extract entire starting line
    if(!(token = strtok(req_text, "\r\n")))
        return -1;

    // quick and dirty regex to verify overall form
    if(regexec(&reg, token, 1, &reg_match, 0) == REG_NOMATCH)
    {
        printf("No regex match found.\n");
        return -1;
    }

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

    // default version will be 1.1, can be modified to match request later
    strcpy(resp->http_ver, "HTTP/1.1");

    if(parseRequest(req_text, &req))
    {
        strcpy(resp->status, BADREQ);
        return -1;
    }

    validateRequest(&req, resp);
}

int main(int argc, char* argv[])
{
    int server_sock, client_sock;
    struct netinfo server_info, client_info;
    pid_t pid;
    int sigset;

    // no more zombies
    signal(SIGCHLD, handleSIGCHLD);
    signal(SIGINT, handleSIGINT);

    if(argc < 2)
    {
        printf("Usage: %s [PORT]\n", argv[0]);
        exit(-1);
    }

    int port_num;
    if((port_num = atoi(argv[1])) == 0)
    {
        printf("Bad port.\n");
        exit(-1);
    }


    // configuring server info
    memset(&server_info, 0, sizeof(server_info));
    server_info.sin.sin_family = AF_INET;
    server_info.sin.sin_port = htons(port_num);
    server_info.sin.sin_addr.s_addr = INADDR_ANY;
    server_info.addr_len = sizeof(server_info.sin);

    // preparing client info
    memset(&client_info, 0, sizeof(client_info));
    client_info.addr_len = sizeof(client_info.sin);

    // create socket
    if((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Socket creation error.\n");
        exit(-1);
    }

    // bind
    if(bind(server_sock, (struct sockaddr *) &server_info.sin, server_info.addr_len) == -1)
    {
        printf("Bind failed.\n");
        exit(-1);
    }

    if(listen(server_sock, MAX_QUEUED_CONNECTIONS) == -1)
    {
        printf("Listen failed.\n");
        exit(-1);
    }

    while(1)
    {
        if((client_sock = accept(server_sock, (struct sockaddr *) &client_info.sin, (socklen_t *) &client_info.addr_len)) == -1)
            printf("Accept failure.\n");


        // parent process
        if((pid = fork()))
        {
            close(client_sock);
            continue;
        }

        // children only
        // children ignore sigint, finishing their transmission
        signal(SIGINT, SIG_IGN);
        // close listening socket
        close(server_sock);

        // BEGIN CONNECTION TASKS
        char request_buf[MAX_REQ_LEN];
        char response_buf[SEND_BUF_SIZE];
        memset(request_buf, 0, sizeof(request_buf));
        memset(response_buf, 0, sizeof(response_buf));

        // recieve inbound transmission
        recv(client_sock, request_buf, MAX_REQ_LEN, 0);

        // generate response to given request
        struct http_resp resp;
        clearResp(&resp);
        int res = processRequest(request_buf, &resp);

        // respond to request
        if(res)
            sprintf(response_buf, "%s %s\r\n\r\n",
            resp.http_ver,
            resp.status);
        else
            sprintf(response_buf, "%s %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\n\r\n",
            resp.http_ver,
            resp.status,
            contentTypeString(resp.fmd_ptr->f_type),
            resp.fmd_ptr->f_size);
            

        sendAll(client_sock, response_buf, strlen(response_buf));

        // send file, if applicable
        if(resp.fmd_ptr->f_ptr != NULL)
        {
            int bytes;
            while((bytes = fread(response_buf, 1, SEND_BUF_SIZE, resp.fmd_ptr->f_ptr)))
                sendAll(client_sock, response_buf, bytes);
        }

        destroyFMD(resp.fmd_ptr);

        // TODO is this needed? is this beneficial
        // shutdown(client_sock, SHUT_RDWR);
        close(client_sock);
        exit(0);
    }
}