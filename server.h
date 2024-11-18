#ifndef __SERVER_H
#define __SERVER_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

/*
 * Feel free to edit any part of codes
 */

#define ERR_EXIT(a) do { perror(a); exit(1); } while(0)

#define TRAIN_NUM 5
#define SEAT_NUM 40
#define TRAIN_ID_START 902001
#define TRAIN_ID_END (TRAIN_ID_START + TRAIN_NUM - 1)
#define FILE_LEN 50
#define MAX_MSG_LEN 512

typedef struct {
    char hostname[512];  // server's hostname
    unsigned short port;  // port to listen
    int listen_fd;  // fd to wait for a new connection
} server;

typedef enum {
    SEAT_UNKNOWN,    // Seat is unknown
    SEAT_CHOSEN,     // Seat is currently being reserved 
    SEAT_PAID        // Seat is already paid for
} SeatStatus;

typedef enum {
    REQUEST_INVALID,        // Initial state, waiting for shift ID
    REQUEST_CHOOSING_SEATS, // Waiting for seat selection or "pay"
    REQUEST_AFTER_PAYMENT   // Waiting for "seat" or "exit"
} RequestStatus;

typedef struct {
    SeatStatus seat_stat[SEAT_NUM];
    struct flock locks[SEAT_NUM]; // To store locks for each seat
    int num_of_chosen_seats;
    int shift_id;
    int train_fd;
} BookingInfo;

typedef struct {
    int conn_fd;
    char host[512];
    char buf[MAX_MSG_LEN];
    int buf_len;
    RequestStatus status;
    int client_id;
    struct timeval start_time;
    struct timeval remaining_time;
    BookingInfo booking_info;
} request;

typedef struct {
    char seat_status[SEAT_NUM]; // Internal seat status
    int seat_locks[SEAT_NUM];   // -1: unlocked, >=0: locked by client_id
} train_info;

// Global variables
extern server svr;  // server
extern request* requestP;  // point to a list of requests
extern train_info trains[TRAIN_NUM];
extern int maxfd;  // size of open file descriptor table, size of request list
extern int num_conn;
extern int alive_conn;

// Function prototypes
void handle_write_server(int fd, char* input_line);
void handle_read_server(int fd, char* input_line);
int handle_read(request* reqP);
int print_train_info(request *reqP);
int is_shift_fully_booked(int shift_id);
int print_booking_info(request *reqP);
int select_seat(request* reqP, int seat_num);
void cancel_booking(request* reqP);
int process_payment(request* reqP);
void getfilepath(char* filepath, int shift_id); // Corrected parameter name
void init_server(unsigned short port);
void init_request(request* reqP);
void free_request(request* reqP);

#endif // __SERVER_H
