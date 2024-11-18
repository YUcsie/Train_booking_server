#include "server.h"
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

fd_set master_set;

const unsigned char IAC_IP[3] = "\xff\xf4\0";
const char *file_prefix = "./csie_trains/train_";
const char *accept_read_header = "ACCEPT_FROM_READ";
const char *accept_write_header = "ACCEPT_FROM_WRITE";
const char *welcome_banner = "======================================\n"
                             " Welcome to CSIE Train Booking System \n"
                             "======================================\n";

const char *lock_msg = ">>> Locked.\n";
const char *exit_msg = ">>> Client exit.\n";
const char *cancel_msg = ">>> You cancel the seat.\n";
const char *full_msg = ">>> The shift is fully booked.\n";
const char *seat_booked_msg = ">>> The seat is booked.\n";
const char *no_seat_msg = ">>> No seat to pay.\n";
const char *book_succ_msg = ">>> Your train booking is successful.\n";
const char *invalid_op_msg = ">>> Invalid operation.\n";

const char *read_shift_msg = "Please select the shift you want to check [902001-902005]: ";
const char *write_shift_msg = "Please select the shift you want to book [902001-902005]: ";
const char *write_seat_msg = "Select the seat [1-40] or type \"pay\" to confirm: ";
const char *write_seat_or_exit_msg = "Type \"seat\" to continue or \"exit\" to quit [seat/exit]: ";

server svr;
request *requestP = NULL;
train_info trains[TRAIN_NUM];
int maxfd;
int num_conn = 1;
int alive_conn = 0;

int get_offset(int seat_num)
{
    int line = (seat_num - 1) / 4;
    int col = (seat_num - 1) % 4;
    return line * 8 + col * 2;
}

void lock_seat(int fd, int seat_num, short lock_type)
{
    struct flock lock;
    lock.l_type = lock_type;
    lock.l_whence = SEEK_SET;
    lock.l_start = get_offset(seat_num);
    lock.l_len = 1;
    fcntl(fd, F_SETLKW, &lock);
}

void unlock_seat(int fd, int seat_num)
{
    struct flock lock;
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = get_offset(seat_num);
    lock.l_len = 1;
    fcntl(fd, F_SETLK, &lock);
}

void trim_whitespace(char *str)
{
    char *end;
    char *start = str;

    while (isspace((unsigned char)*start))
        start++;

    if (*start == 0)
    {
        str[0] = '\0';
        return;
    }

    if (start != str)
    {
        memmove(str, start, strlen(start) + 1);
    }

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    *(end + 1) = '\0';
}

ssize_t writeall(int fd, const void *buffer, size_t count)
{
    size_t bytes_written = 0;
    const char *buf = buffer;

    while (bytes_written < count)
    {
        ssize_t res = write(fd, buf + bytes_written, count - bytes_written);
        if (res < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EWOULDBLOCK || errno == EAGAIN)
            {

                continue;
            }
            else
            {
                return -1;
            }
        }
        bytes_written += res;
    }
    return bytes_written;
}

void handle_write_server(int fd, char *input_line)
{

    trim_whitespace(input_line);

    if (strlen(input_line) >= MAX_MSG_LEN)
    {
        fprintf(stderr, "Invalid operation: input length exceeds limit from fd %d.\n", fd);
        writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }

    if (strcmp(input_line, "exit") == 0)
    {
        fprintf(stderr, "Client fd %d requested exit.\n", fd);
        writeall(requestP[fd].conn_fd, exit_msg, strlen(exit_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }

    if (requestP[fd].status == REQUEST_INVALID)
    {

        if (strcmp(input_line, "pay") == 0 || strcmp(input_line, "seat") == 0)
        {
            fprintf(stderr, "Invalid command '%s' in REQUEST_INVALID state from fd %d.\n", input_line, fd);
            writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
            close(requestP[fd].conn_fd);
            FD_CLR(fd, &master_set);
            free_request(&requestP[fd]);
            return;
        }

        char *endptr;
        long shift_id = strtol(input_line, &endptr, 10);
        if (*endptr != '\0' || shift_id < TRAIN_ID_START || shift_id > TRAIN_ID_END)
        {
            fprintf(stderr, "Invalid shift ID '%s' from fd %d.\n", input_line, fd);
            writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
            close(requestP[fd].conn_fd);
            FD_CLR(fd, &master_set);
            free_request(&requestP[fd]);
            return;
        }

        requestP[fd].booking_info.shift_id = (int)shift_id;

        if (is_shift_fully_booked(requestP[fd].booking_info.shift_id))
        {
            fprintf(stderr, "Shift %d is fully booked. Notifying fd %d.\n", requestP[fd].booking_info.shift_id, fd);
            writeall(requestP[fd].conn_fd, full_msg, strlen(full_msg));

            writeall(requestP[fd].conn_fd, write_shift_msg, strlen(write_shift_msg));
            printf("\n");
            requestP[fd].status = REQUEST_INVALID;
            fprintf(stderr, "Client fd %d remains in REQUEST_INVALID state.\n", fd);
        }
        else
        {

            print_booking_info(&requestP[fd]);

            requestP[fd].status = REQUEST_CHOOSING_SEATS;
            fprintf(stderr, "Client fd %d transitioned to REQUEST_CHOOSING_SEATS state.\n", fd);

            writeall(requestP[fd].conn_fd, write_seat_msg, strlen(write_seat_msg));
            printf("\n");
        }
    }
    else if (requestP[fd].status == REQUEST_CHOOSING_SEATS)
    {

        if ((strcmp(input_line, "pay") == 0) || (strcmp(input_line, "pay1") == 0) || (strcmp(input_line, "pay2") == 0))
        {

            if (requestP[fd].booking_info.num_of_chosen_seats == 0)
            {

                fprintf(stderr, "Client fd %d attempted to pay without selecting seats.\n", fd);
                writeall(requestP[fd].conn_fd, no_seat_msg, strlen(no_seat_msg));
                print_booking_info(&requestP[fd]);

                writeall(requestP[fd].conn_fd, write_seat_msg, strlen(write_seat_msg));
                printf("\n");
            }
            else
            {

                if (process_payment(&requestP[fd]) == 0)
                {
                    fprintf(stderr, "Client fd %d successfully paid for seats.\n", fd);
                    writeall(requestP[fd].conn_fd, book_succ_msg, strlen(book_succ_msg));
                    print_booking_info(&requestP[fd]);

                    requestP[fd].status = REQUEST_AFTER_PAYMENT;
                    fprintf(stderr, "Client fd %d transitioned to REQUEST_AFTER_PAYMENT state.\n", fd);

                    writeall(requestP[fd].conn_fd, write_seat_or_exit_msg, strlen(write_seat_or_exit_msg));
                    printf("\n");
                }
                else
                {

                    fprintf(stderr, "Payment failed for client fd %d.\n", fd);
                    writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
                    close(requestP[fd].conn_fd);
                    FD_CLR(fd, &master_set);
                    free_request(&requestP[fd]);
                    return;
                }
            }
        }
        else if (strcmp(input_line, "exit") == 0)
        {

            fprintf(stderr, "Client fd %d requested exit during seat selection.\n", fd);
            writeall(requestP[fd].conn_fd, exit_msg, strlen(exit_msg));
            close(requestP[fd].conn_fd);
            FD_CLR(fd, &master_set);
            free_request(&requestP[fd]);
            return;
        }
        else
        {

            char *endptr;
            long seat_num = strtol(input_line, &endptr, 10);
            if (*endptr != '\0' || seat_num < 1 || seat_num > SEAT_NUM)
            {

                fprintf(stderr, "Invalid seat number '%s' from fd %d.\n", input_line, fd);
                writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
                close(requestP[fd].conn_fd);
                FD_CLR(fd, &master_set);
                free_request(&requestP[fd]);
                return;
            }
            else
            {

                int select_result = select_seat(&requestP[fd], (int)seat_num);
                if (select_result == 0)
                {

                    fprintf(stderr, "Client fd %d successfully selected/canceled seat %d.\n", fd, (int)seat_num);
                    print_booking_info(&requestP[fd]);
                }
                else if (select_result == -1)
                {

                    fprintf(stderr, "Client fd %d attempted to book already booked seat %d.\n", fd, (int)seat_num);
                    print_booking_info(&requestP[fd]);
                }

                writeall(requestP[fd].conn_fd, write_seat_msg, strlen(write_seat_msg));
                printf("\n");
            }
        }
    }
    else if (requestP[fd].status == REQUEST_AFTER_PAYMENT)
    {

        if (strcmp(input_line, "seat") == 0)
        {

            fprintf(stderr, "Client fd %d chose to continue selecting seats.\n", fd);

            requestP[fd].status = REQUEST_CHOOSING_SEATS;
            fprintf(stderr, "Client fd %d transitioned back to REQUEST_CHOOSING_SEATS state.\n", fd);

            if (print_booking_info(&requestP[fd]) == -1)
            {
                fprintf(stderr, "Failed to print booking info for fd %d.\n", fd);
            }

            writeall(requestP[fd].conn_fd, write_seat_msg, strlen(write_seat_msg));
            printf("\n");
        }
        else if (strcmp(input_line, "exit") == 0)
        {

            fprintf(stderr, "Client fd %d requested exit after payment.\n", fd);
            writeall(requestP[fd].conn_fd, exit_msg, strlen(exit_msg));
            close(requestP[fd].conn_fd);
            FD_CLR(fd, &master_set);
            free_request(&requestP[fd]);
            return;
        }
        else
        {

            fprintf(stderr, "Invalid input '%s' from fd %d after payment.\n", input_line, fd);
            writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
            close(requestP[fd].conn_fd);
            FD_CLR(fd, &master_set);
            free_request(&requestP[fd]);
            return;
        }
    }
    else
    {

        fprintf(stderr, "Client fd %d in invalid state %d. Closing connection.\n", fd, requestP[fd].status);
        writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }
}

int handle_read(request *reqP)
{
    int r;
    char buf[512];
    memset(buf, 0, sizeof(buf));

    r = read(reqP->conn_fd, buf, sizeof(buf) - 1);
    if (r < 0)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {

            return 2;
        }
        else
        {

            fprintf(stderr, "Read error on fd %d.\n", reqP->conn_fd);
            return -1;
        }
    }
    if (r == 0)
        return 0;

    buf[r] = '\0';

    if (reqP->buf_len + r >= MAX_MSG_LEN)
    {

        fprintf(stderr, "Input length exceeds limit from fd %d.\n", reqP->conn_fd);
        writeall(reqP->conn_fd, invalid_op_msg, strlen(invalid_op_msg));
        close(reqP->conn_fd);
        FD_CLR(reqP->conn_fd, &master_set);
        free_request(reqP);
        return -1;
    }

    memcpy(reqP->buf + reqP->buf_len, buf, r);
    reqP->buf_len += r;
    reqP->buf[reqP->buf_len] = '\0';

    if (strchr(reqP->buf, '\n') != NULL)
    {
        gettimeofday(&reqP->start_time, NULL);
        return 1;
    }
    else
    {
        return 2;
    }
}

int print_train_info(request *reqP)
{
    int shift_id = reqP->booking_info.shift_id;
    char filepath[FILE_LEN];
    getfilepath(filepath, shift_id);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file %s for reading.\n", filepath);
        return -1;
    }

    struct flock lock;
    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(fd, F_SETLKW, &lock);

    char file_buffer[MAX_MSG_LEN];
    memset(file_buffer, 0, sizeof(file_buffer));
    int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
    if (ret < 0)
    {
        fprintf(stderr, "Error reading file %s.\n", filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return -1;
    }
    file_buffer[ret] = '\0';

    char seat_status[SEAT_NUM];
    memset(seat_status, 0, sizeof(seat_status));
    int seat_count = 0;
    for (char *p = file_buffer; *p != '\0'; p++)
    {
        if (*p == '0' || *p == '1' || *p == '2')
        {
            if (seat_count < SEAT_NUM)
            {
                seat_status[seat_count++] = *p;
            }
            else
            {
                break;
            }
        }
    }

    if (seat_count != SEAT_NUM)
    {
        fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return -1;
    }

    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &lock);
    close(fd);

    char formatted_map[MAX_MSG_LEN];
    memset(formatted_map, 0, sizeof(formatted_map));
    int pos = 0;
    int seats_per_line = 4;

    for (int i = 0; i < SEAT_NUM; i++)
    {
        if (pos < MAX_MSG_LEN - 2)
        {
            formatted_map[pos++] = seat_status[i];

            if ((i + 1) % seats_per_line == 0)
            {
                formatted_map[pos++] = '\n';
            }
            else
            {
                formatted_map[pos++] = ' ';
            }
        }
        else
        {
            break;
        }
    }

    formatted_map[pos] = '\0';

    fprintf(stderr, "Sending seat map to fd %d:\n%s\n", reqP->conn_fd, formatted_map);
    writeall(reqP->conn_fd, formatted_map, strlen(formatted_map));

    return 0;
}

void handle_read_server(int fd, char *input_line)
{

    trim_whitespace(input_line);

    if (strcmp(input_line, "exit") == 0)
    {

        fprintf(stderr, "Client fd %d requested exit.\n", fd);
        writeall(requestP[fd].conn_fd, exit_msg, strlen(exit_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }

    if (strlen(input_line) >= MAX_MSG_LEN)
    {
        fprintf(stderr, "Invalid operation: input length exceeds limit from fd %d.\n", fd);
        writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }

    char *endptr;
    long shift_id = strtol(input_line, &endptr, 10);

    if (*endptr == '\0' && shift_id >= TRAIN_ID_START && shift_id <= TRAIN_ID_END)
    {
        requestP[fd].booking_info.shift_id = (int)shift_id;

        if (print_train_info(&requestP[fd]) == -1)
        {
            writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));

            writeall(requestP[fd].conn_fd, read_shift_msg, strlen(read_shift_msg));

            printf("\n");
        }
        else
        {

            writeall(requestP[fd].conn_fd, read_shift_msg, strlen(read_shift_msg));
            printf("\n");
        }
    }
    else
    {

        fprintf(stderr, "Invalid shift ID '%s' from fd %d.\n", input_line, fd);
        writeall(requestP[fd].conn_fd, invalid_op_msg, strlen(invalid_op_msg));
        close(requestP[fd].conn_fd);
        FD_CLR(fd, &master_set);
        free_request(&requestP[fd]);
        return;
    }
}

void getfilepath(char *filepath, int shift_id)
{
    snprintf(filepath, FILE_LEN, "%s%d", file_prefix, shift_id);
}

int is_shift_fully_booked(int shift_id)
{
    char filepath[FILE_LEN];
    getfilepath(filepath, shift_id);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file %s for checking full status.\n", filepath);
        return 1;
    }

    struct flock lock;
    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(fd, F_SETLKW, &lock);

    char file_buffer[MAX_MSG_LEN];
    memset(file_buffer, 0, sizeof(file_buffer));
    int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
    if (ret < 0)
    {
        fprintf(stderr, "Error reading file %s for full status.\n", filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return 1;
    }
    file_buffer[ret] = '\0';

    char seat_status[SEAT_NUM];
    memset(seat_status, 0, sizeof(seat_status));
    int seat_count = 0;
    for (char *p = file_buffer; *p != '\0'; p++)
    {
        if (*p == '0' || *p == '1' || *p == '2')
        {
            if (seat_count < SEAT_NUM)
            {
                seat_status[seat_count++] = *p;
            }
            else
            {
                break;
            }
        }
    }

    if (seat_count != SEAT_NUM)
    {
        fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return 1;
    }

    int is_full = 1;
    for (int i = 0; i < SEAT_NUM; i++)
    {
        if (seat_status[i] == '0')
        {
            is_full = 0;
            break;
        }
    }

    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &lock);
    close(fd);

    return is_full;
}

int compare_ints(const void *a, const void *b)
{
    int int_a = *(const int *)a;
    int int_b = *(const int *)b;
    return int_a - int_b;
}

void accept_new_connection()
{
    struct sockaddr_in cliaddr;
    socklen_t clilen = sizeof(cliaddr);

    int conn_fd = accept(svr.listen_fd, (struct sockaddr *)&cliaddr, &clilen);
    if (conn_fd < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
            return;
        if (errno == ENFILE)
        {
            fprintf(stderr, "Out of file descriptor table\n");
            return;
        }
        ERR_EXIT("accept");
    }

    int flags = fcntl(conn_fd, F_GETFL, 0);
    fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

    FD_SET(conn_fd, &master_set);
    if (conn_fd > maxfd)
        maxfd = conn_fd;

    init_request(&requestP[conn_fd]);
    requestP[conn_fd].conn_fd = conn_fd;
    strcpy(requestP[conn_fd].host, inet_ntoa(cliaddr.sin_addr));

    fprintf(stderr, "Accepted new connection: fd %d from %s\n", conn_fd, requestP[conn_fd].host);

    writeall(conn_fd, welcome_banner, strlen(welcome_banner));

#ifdef READ_SERVER
    writeall(conn_fd, read_shift_msg, strlen(read_shift_msg));
    printf("\n");
#else
    writeall(conn_fd, write_shift_msg, strlen(write_shift_msg));
    printf("\n");
#endif

    gettimeofday(&requestP[conn_fd].start_time, NULL);
}

int print_booking_info(request *reqP)
{
    char buf[MAX_MSG_LEN];
    memset(buf, 0, sizeof(buf));

    char chosen_seats[SEAT_NUM * 3] = {0};
    char paid_seats[SEAT_NUM * 3] = {0};

    int chosen_seats_list[SEAT_NUM];
    int num_chosen = 0;

    int paid_seats_list[SEAT_NUM];
    int num_paid = 0;

    for (int i = 0; i < SEAT_NUM; i++)
    {
        if (reqP->booking_info.seat_stat[i] == SEAT_CHOSEN)
        {
            chosen_seats_list[num_chosen++] = i + 1;
        }
        else if (reqP->booking_info.seat_stat[i] == SEAT_PAID)
        {
            paid_seats_list[num_paid++] = i + 1;
        }
    }

    if (num_chosen > 0)
    {
        qsort(chosen_seats_list, num_chosen, sizeof(int), compare_ints);
        for (int i = 0; i < num_chosen; i++)
        {
            if (i > 0)
            {
                strcat(chosen_seats, ",");
            }
            char seat_num_str[4];
            snprintf(seat_num_str, sizeof(seat_num_str), "%d", chosen_seats_list[i]);
            strcat(chosen_seats, seat_num_str);
        }
    }

    if (num_paid > 0)
    {
        qsort(paid_seats_list, num_paid, sizeof(int), compare_ints);
        for (int i = 0; i < num_paid; i++)
        {
            if (i > 0)
            {
                strcat(paid_seats, ",");
            }
            char seat_num_str[4];
            snprintf(seat_num_str, sizeof(seat_num_str), "%d", paid_seats_list[i]);
            strcat(paid_seats, seat_num_str);
        }
    }

    snprintf(buf, sizeof(buf),
             "\nBooking info\n"
             "|- Shift ID: %d\n"
             "|- Chose seat(s): %s\n"
             "|- Paid: %s\n\n",
             reqP->booking_info.shift_id,
             num_chosen == 0 ? "" : chosen_seats,
             num_paid == 0 ? "" : paid_seats);

    writeall(reqP->conn_fd, buf, strlen(buf));

    return 0;
}

int select_seat(request *reqP, int seat_num)
{
    char filepath[FILE_LEN];
    getfilepath(filepath, reqP->booking_info.shift_id);

    int fd = open(filepath, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file %s for seat selection.\n", filepath);
        ERR_EXIT("open");
    }

    lock_seat(fd, seat_num, F_WRLCK);

    char file_buffer[MAX_MSG_LEN];
    memset(file_buffer, 0, sizeof(file_buffer));
    int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
    if (ret < 0)
    {
        fprintf(stderr, "Error reading file %s.\n", filepath);
        unlock_seat(fd, seat_num);
        close(fd);
        return -1;
    }
    file_buffer[ret] = '\0';

    char seat_status[SEAT_NUM];
    memset(seat_status, 0, sizeof(seat_status));
    int seat_count = 0;
    for (char *p = file_buffer; *p != '\0'; p++)
    {
        if (*p == '0' || *p == '1' || *p == '2')
        {
            if (seat_count < SEAT_NUM)
            {
                seat_status[seat_count++] = *p;
            }
            else
            {
                break;
            }
        }
    }

    if (seat_count != SEAT_NUM)
    {
        fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filepath);
        unlock_seat(fd, seat_num);
        close(fd);
        return -1;
    }

    if (seat_status[seat_num - 1] == '1')
    {

        fprintf(stderr, "Seat %d in shift %d is already booked.\n", seat_num, reqP->booking_info.shift_id);
        writeall(reqP->conn_fd, seat_booked_msg, strlen(seat_booked_msg));
        unlock_seat(fd, seat_num);
        close(fd);
        return -1;
    }

    if (reqP->booking_info.seat_stat[seat_num - 1] == SEAT_CHOSEN)
    {

        reqP->booking_info.seat_stat[seat_num - 1] = SEAT_UNKNOWN;
        reqP->booking_info.num_of_chosen_seats--;

        seat_status[seat_num - 1] = '0';

        int offset = get_offset(seat_num);

        lseek(fd, offset, SEEK_SET);
        writeall(fd, &seat_status[seat_num - 1], 1);

        fprintf(stderr, "Client fd %d canceled seat %d in shift %d.\n", reqP->conn_fd, seat_num, reqP->booking_info.shift_id);
        writeall(reqP->conn_fd, cancel_msg, strlen(cancel_msg));

        unlock_seat(fd, seat_num);
        close(fd);
        return 0;
    }

    reqP->booking_info.seat_stat[seat_num - 1] = SEAT_CHOSEN;
    reqP->booking_info.num_of_chosen_seats++;

    seat_status[seat_num - 1] = '2';

    int offset = get_offset(seat_num);

    lseek(fd, offset, SEEK_SET);
    writeall(fd, &seat_status[seat_num - 1], 1);

    char msg[64];
    fprintf(stderr, "Client fd %d selected seat %d in shift %d.\n", reqP->conn_fd, seat_num, reqP->booking_info.shift_id);
    writeall(reqP->conn_fd, msg, strlen(msg));

    unlock_seat(fd, seat_num);
    close(fd);

    return 0;
}

void cancel_booking(request *reqP)
{
    char filepath[FILE_LEN];
    getfilepath(filepath, reqP->booking_info.shift_id);

    int fd = open(filepath, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file %s for cancelling booking.\n", filepath);
        ERR_EXIT("open");
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(fd, F_SETLKW, &lock);

    char file_buffer[MAX_MSG_LEN];
    memset(file_buffer, 0, sizeof(file_buffer));
    int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
    if (ret < 0)
    {
        fprintf(stderr, "Error reading file %s.\n", filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return;
    }
    file_buffer[ret] = '\0';

    char seat_status[SEAT_NUM];
    memset(seat_status, 0, sizeof(seat_status));
    int seat_count = 0;
    for (char *p = file_buffer; *p != '\0'; p++)
    {
        if (*p == '0' || *p == '1' || *p == '2')
        {
            if (seat_count < SEAT_NUM)
            {
                seat_status[seat_count++] = *p;
            }
            else
            {
                break;
            }
        }
    }

    if (seat_count != SEAT_NUM)
    {
        fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return;
    }

    for (int i = 0; i < SEAT_NUM; i++)
    {
        if (reqP->booking_info.seat_stat[i] == SEAT_CHOSEN)
        {
            seat_status[i] = '0';
            reqP->booking_info.seat_stat[i] = SEAT_UNKNOWN;

            int seat_num = i + 1;
            int offset = get_offset(seat_num);

            lseek(fd, offset, SEEK_SET);
            writeall(fd, &seat_status[i], 1);
        }
    }

    reqP->booking_info.num_of_chosen_seats = 0;

    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &lock);
    close(fd);

    fprintf(stderr, "Cancelled all bookings for client fd %d in shift %d.\n", reqP->conn_fd, reqP->booking_info.shift_id);
}

int process_payment(request *reqP)
{
    char filepath[FILE_LEN];
    getfilepath(filepath, reqP->booking_info.shift_id);

    int fd = open(filepath, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file %s for payment.\n", filepath);
        ERR_EXIT("open");
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(fd, F_SETLKW, &lock);

    char file_buffer[MAX_MSG_LEN];
    memset(file_buffer, 0, sizeof(file_buffer));
    int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
    if (ret < 0)
    {
        fprintf(stderr, "Error reading file %s.\n", filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return -1;
    }
    file_buffer[ret] = '\0';

    char seat_status[SEAT_NUM];
    memset(seat_status, 0, sizeof(seat_status));
    int seat_count = 0;
    for (char *p = file_buffer; *p != '\0'; p++)
    {
        if (*p == '0' || *p == '1' || *p == '2')
        {
            if (seat_count < SEAT_NUM)
            {
                seat_status[seat_count++] = *p;
            }
            else
            {
                break;
            }
        }
    }

    if (seat_count != SEAT_NUM)
    {
        fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filepath);

        lock.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
        return -1;
    }

    for (int i = 0; i < SEAT_NUM; i++)
    {
        if (reqP->booking_info.seat_stat[i] == SEAT_CHOSEN)
        {
            seat_status[i] = '1';
            reqP->booking_info.seat_stat[i] = SEAT_PAID;

            int seat_num = i + 1;
            int offset = get_offset(seat_num);

            lseek(fd, offset, SEEK_SET);
            writeall(fd, &seat_status[i], 1);
        }
    }

    reqP->booking_info.num_of_chosen_seats = 0;

    reqP->status = REQUEST_AFTER_PAYMENT;
    fprintf(stderr, "Client fd %d transitioned to REQUEST_AFTER_PAYMENT state.\n", reqP->conn_fd);

    lock.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &lock);
    close(fd);

    fprintf(stderr, "Client fd %d successfully paid for seats in shift %d.\n", reqP->conn_fd, reqP->booking_info.shift_id);
    return 0;
}

int main(int argc, char **argv)
{

    signal(SIGPIPE, SIG_IGN);

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        exit(1);
    }

    char buf[MAX_MSG_LEN * 2], filename[FILE_LEN];
    int i, j;

    for (i = TRAIN_ID_START, j = 0; i <= TRAIN_ID_END; i++, j++)
    {
        getfilepath(filename, i);
        int fd = open(filename, O_RDONLY);
        if (fd < 0)
        {
            fprintf(stderr, "Error opening seat file %s.\n", filename);
            ERR_EXIT("open");
        }

        char file_buffer[MAX_MSG_LEN];
        int ret = read(fd, file_buffer, sizeof(file_buffer) - 1);
        if (ret < 0)
        {
            perror("read seat map");
            exit(1);
        }
        file_buffer[ret] = '\0';

        int seat_count = 0;
        for (char *p = file_buffer; *p != '\0'; p++)
        {
            if (*p == '0' || *p == '1' || *p == '2')
            {
                if (seat_count < SEAT_NUM)
                {
                    trains[j].seat_status[seat_count++] = *p;
                }
                else
                {

                    break;
                }
            }
        }

        if (seat_count != SEAT_NUM)
        {
            fprintf(stderr, "Error: Expected %d seat statuses, but found %d in file %s\n", SEAT_NUM, seat_count, filename);
            exit(1);
        }
        else
        {
        }

        for (int k = 0; k < SEAT_NUM; k++)
        {
            trains[j].seat_locks[k] = -1;
        }

        close(fd);
    }

    init_server((unsigned short)atoi(argv[1]));

    maxfd = svr.listen_fd;
    FD_ZERO(&master_set);
    FD_SET(svr.listen_fd, &master_set);

    while (1)
    {
        fd_set read_fds = master_set;
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int nready = select(maxfd + 1, &read_fds, NULL, NULL, &tv);
        if (nready < 0)
        {
            if (errno == EINTR)
                continue;
            ERR_EXIT("select");
        }

        if (FD_ISSET(svr.listen_fd, &read_fds))
        {

            accept_new_connection();
            nready--;
            if (nready <= 0)
                continue;
        }

        for (int fd = 0; fd <= maxfd; fd++)
        {
            if (fd != svr.listen_fd && FD_ISSET(fd, &read_fds))
            {

                int ret = handle_read(&requestP[fd]);
                if (ret == 0)
                {

                    fprintf(stderr, "Client fd %d disconnected.\n", fd);
                    FD_CLR(fd, &master_set);
                    free_request(&requestP[fd]);
                }
                else if (ret == -1)
                {

                    fprintf(stderr, "Read error on fd %d. Closing connection.\n", fd);
                    FD_CLR(fd, &master_set);
                    free_request(&requestP[fd]);
                }
                else if (ret == 1)
                {

                    while (1)
                    {

                        char *newline_pos = strchr(requestP[fd].buf, '\n');
                        if (!newline_pos)
                        {
                            break;
                        }

                        *newline_pos = '\0';

                        char line[MAX_MSG_LEN];
                        strncpy(line, requestP[fd].buf, sizeof(line));
                        line[sizeof(line) - 1] = '\0';

                        fprintf(stderr, "Processing line from fd %d: %s\n", fd, line);

#ifdef READ_SERVER
                        handle_read_server(fd, line);
#elif defined WRITE_SERVER
                        handle_write_server(fd, line);
#endif

                        newline_pos++;

                        while (*newline_pos == '\n' || *newline_pos == '\r')
                        {
                            newline_pos++;
                        }

                        int line_len = newline_pos - requestP[fd].buf;
                        int remaining_len = requestP[fd].buf_len - line_len;

                        if (remaining_len > 0)
                        {
                            memmove(requestP[fd].buf, newline_pos, remaining_len);
                            requestP[fd].buf_len = remaining_len;
                            requestP[fd].buf[remaining_len] = '\0';
                        }
                        else
                        {

                            requestP[fd].buf_len = 0;
                            requestP[fd].buf[0] = '\0';
                        }
                    }
                }
            }
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        for (int fd = 0; fd <= maxfd; fd++)
        {
            if (requestP[fd].conn_fd != -1 && fd != svr.listen_fd)
            {
                double elapsed = now.tv_sec - requestP[fd].start_time.tv_sec +
                                 (now.tv_usec - requestP[fd].start_time.tv_usec) / 1000000.0;
                if (elapsed >= 5.0)
                {
                    fprintf(stderr, "Connection fd %d timed out after %.2f seconds. Cancelling booking.\n", fd, elapsed);
                    cancel_booking(&requestP[fd]);
                    FD_CLR(fd, &master_set);
                    free_request(&requestP[fd]);
                }
            }
        }
    }

    free(requestP);
    close(svr.listen_fd);

    return 0;
}

#include <fcntl.h>

void init_request(request *reqP)
{
    reqP->conn_fd = -1;
    reqP->buf_len = 0;
    reqP->status = REQUEST_INVALID;
    memset(&reqP->booking_info, 0, sizeof(reqP->booking_info));
    memset(reqP->buf, 0, sizeof(reqP->buf));
    gettimeofday(&reqP->start_time, NULL);
}

void free_request(request *reqP)
{

    if (reqP->conn_fd >= 0)
    {
        close(reqP->conn_fd);
        reqP->conn_fd = -1;
    }
    reqP->buf_len = 0;
    reqP->status = REQUEST_INVALID;
    memset(&reqP->booking_info, 0, sizeof(reqP->booking_info));
    memset(reqP->buf, 0, sizeof(reqP->buf));
}

void init_server(unsigned short port)
{
    struct sockaddr_in servaddr;
    int tmp;

    gethostname(svr.hostname, sizeof(svr.hostname));
    svr.port = port;

    svr.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (svr.listen_fd < 0)
        ERR_EXIT("socket");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    tmp = 1;
    if (setsockopt(svr.listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&tmp, sizeof(tmp)) < 0)
    {
        ERR_EXIT("setsockopt");
    }
    if (bind(svr.listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        ERR_EXIT("bind");
    }
    if (listen(svr.listen_fd, 1024) < 0)
    {
        ERR_EXIT("listen");
    }

    requestP = (request *)malloc(sizeof(request) * FD_SETSIZE);
    if (requestP == NULL)
    {
        ERR_EXIT("out of memory allocating all requests");
    }
    for (int i = 0; i < FD_SETSIZE; i++)
    {
        init_request(&requestP[i]);
    }
    requestP[svr.listen_fd].conn_fd = svr.listen_fd;
    strcpy(requestP[svr.listen_fd].host, svr.hostname);

    return;
}
