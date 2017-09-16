#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

int main() {

    int fp;

    int16_t single_val_1 = 0;

    char vals_8bits[] = {0, 0, 0, 0, 1, 0, 0, 0};
    int16_t vals_16bits[] = {0, 0, 1, 1};

    char read_buf_8bits[2];
    int16_t read_buf_16bits;

    //Open the dev file for reading and writing (file position default to 0)
    fp = open("/dev/rsa", O_RDWR);
    if(fp < 0){
      printf("Failed to open file\n");
      return -1;
    }
    else
      printf("File opened successfully\n");

    //Write 2 bytes from single_val_1 to dev file in position 0 (default)
    printf("Write 2 bytes from single_val_1 to dev file in position 0\n");
    write(fp, &single_val_1, 2);

    //Set the file position to 1
    //File position is stored in increments of 16 bits, so position 1 = reg0(31 downto 16)
    lseek(fp, 1, 0);
    printf("Set the file position to 1\n");

    //Write 1 byte from single_val_1 to dev file in position 1
    //Because single_val_1 = 0x0001, this will write '1' to first 8 bits starting in position 1
    // so reg0(31 downto 16)= 0x0001 (assuming all '0's in upper 8 bits)
    write(fp, &single_val_1, 1);
    printf("Write 1 byte from single_val_1 to dev file in position 1\n");

    //Increment the file position by 2 to position 3
    //The third parameter here chooses whether to increment or set (1 or 0 respectively)
    //Typically recommended to set and use 0 instead (imo) i.e. lseek(fp, 3, 0);
    //position 3 = reg1(31 downto 16)
    lseek(fp, 2, 1);
    printf("Increment the file position by 2 to position 3\n");

    //Write 2 bytes from single_val_1 to dev file in position 3
    write(fp, &single_val_1, 2);
    printf("Write 2 bytes from single_val_1 to dev file in position 3\n");

    //Sleep
    sleep(3);
    printf("Sleep 3\n");

    //Set the file position back to the start to position 0
    lseek(fp, 0, 0);
    printf("Set the file position back to the start to position 0\n");

    //Write 8 bytes from the vals_8bits array into fp
    //This will make the first two registers hold the following values:
    //reg0=0x00000000   reg1=0x00010000
    write(fp, &vals_8bits, 8);
    printf("Write 8 bytes from the vals_8bits array into fp\n");

    //Write 8 bytes from the vals_16bits array into fp
    //This will make the first two registers hold the following values:
    //reg0=0x00000000   reg1=0x00010001
    write(fp, &vals_16bits, 8);
    printf("Write 8 bytes from the vals_16bits array into fp\n");

    //Set the file position to position 2
    lseek(fp, 2, 0);
    printf("Set the file position to position 2\n");

    //Read 2 bytes from dev file and store them in read_buf_8bits
    //This will read reg1(15 downto 0) starting with LSB first
    read(fp, &read_buf_8bits, 2);
    printf("Read 2 bytes from dev file and store them in read_buf_8bits\n");

    //Should print out "Read: [0]1 [1]0" because we wrote '1' to this 16-bit location
    //and we are storing in 8-bit chunks
    printf("Read: [0]%d [1]%d\n", read_buf_8bits[0], read_buf_8bits[1]);

    //Read 2 bytes from dev file and store them in read_buf_16bits
    //This will read reg1(15 downto 0) starting with LSB first
    read(fp, &read_buf_16bits, 2);
    printf("Read 2 bytes from dev file and store them in read_buf_16bits\n");

    //Should print out "Read: 1" because we wrote '1' to this 16-bit location
    //and we are storing in a 16-bit chunk
    printf("Read: %d", read_buf_16bits);

    //Close the dev file
    //Upon reopeon, the file position will be reset back to 0
    close(fp);

    return 0;
}
