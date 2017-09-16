// RSA_Test.c - RSA Core Test
//  Author: Taylor JL Whitaker - SmartES Lab
//  Date: 13 June 2017
//
//  This file is made to test the BasicRSA IP from Trust-Hub.org
//    utilized for trojan evaluations with embedded linux applications.
//    It encrypts a value with a private key and decrypts the result with
//    the public key. Success if final result is equal to intial input.
//
//  RSA Device Memory (Eight 32 bit registers, 28 bytes used)
//    [0] Reset     (0)
//    [1] SWReady   (0)
//    [2] Exponent  (31 downto 0)
//    [3] Modulus   (31 downto 0)
//    [4] DataIn    (31 downto 0)
//    [5] HWReady   (0)
//    [6] DataOut   (31 downto 0)
//    [8] Empty

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

void print(int fp, int* registers){

  // Move to file start
  lseek(fp, 0, 0);

  // Bytes to read: 28
  read(fp, registers, 28);
  // printf("Reset: \t\t%08x\n", *(registers));
  // printf("SWReady: \t%08x\n", *(registers+1));
  // printf("Exponent: \t%08x\n", *(registers+2));
  // printf("Modulus: \t%08x\n", *(registers+3));
  // printf("DataIn: \t%08x\n", *(registers+4));
  // printf("HWReady: \t%08x\n", *(registers+5));
  // printf("DataOut: \t%08x\n", *(registers+6));

  return;
}

int main() {

  // File position
  int fp;

  // High/Low
  int High = 1;
  int Low = 0;

  // Integers are 32 bits, same as device registers
  int PubExp = 11;
  int PrivExp = 23;
  int Mod = 301;
  int DataIn = 10;
  int DataOut = 0;

  // RSA registers
  int registers[] = {0,0,0,0,0,0,0};


  // Open the dev file for reading and writing (file position default to 0)
  fp = open("/dev/rsa", O_RDWR);
  if(fp < 0){
    printf("Failed to open file\n");
    return -1;
  }
  else
    printf("File opened successfully\n");


  // Read the device memory
  print(fp, &(*registers));


  // Reset RSA core
  write(fp, &High, 4);
  // printf("Writing Reset: High\n");

  write(fp, &Low, 4);
  // printf("Writing Reset: Low\n");


  // Move to Exponent register
  lseek(fp, 2, 0);
  // printf("Set the file position to register 2\n");

  // Set Exponent
  write(fp, &PrivExp, 4);
  // printf("Writing Exponent\n");


  // Move to Modulus register
  lseek(fp, 3, 0);
  // printf("Set the file position to register 3\n");

  // Set Modulus
  write(fp, &Mod, 4);
  // printf("Writing Modulus\n");


  // Move to DataIn register
  lseek(fp, 4, 0);
  // printf("Set the file position to register 4\n");

  // Set DataIn
  write(fp, &DataIn, 4);
  // printf("Writing DataIn\n");


  // Toggle SWReady
  lseek(fp, 1, 0);
  // printf("Set the file position to register 1\n");

  write(fp, &High, 4);
  // printf("Writing SWReady: High\n");

  write(fp, &Low, 4);
  // printf("Writing SWReady: Low\n");


  // Print resulting register states
  print(fp, &(*registers));


  // Move to Exponent register
  lseek(fp, 2, 0);
  // printf("Set the file position to register 2\n");

  // Set Exponent
  write(fp, &PubExp, 4);
  // printf("Writing Exp\n");


  // Move to DataIn register
  lseek(fp, 4, 0);
  // printf("Set the file position to register 4\n");

  // Set DataIn as previous DataOut (cipher)
  DataOut = registers[6];

  write(fp, &DataOut, 4);
  // printf("Writing DataIn\n");


  // Toggle SWReady
  lseek(fp, 1, 0);
  // printf("Set the file position to register 1\n");

  write(fp, &High, 4);
  // printf("Writing SWReady: High\n");

  write(fp, &Low, 4);
  // printf("Writing SWReady: Low\n");


  // Print resulting register states
  print(fp, &(*registers));


  // Did RSA work?
  if (registers[6] == DataIn)
    printf("RSA TEST SUCCESS\n");
  else
    printf("RSA TEST FAILURE\n");

  // Close the dev file
  close(fp);

  return 0;
}
