// RSA_Write .c - RSA Device Memory Write
//  Author: Taylor JL Whitaker - SmartES Lab
//  Date: 14 June 2017

//  This file is made to write the BasicRSA IP from Trust-Hub.org
//    utilized for trojan evaluations with embedded linux applications.

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
#include <string.h>


int main( int argc, char *argv[] ) {

  // File
  int fp;
  char* Filename;

  // Catch string part of strtol
  char* ret;

  // Register toggles
  int writeReset = 0;
  int writeReady = 0;
  int writeExp = 0;
  int writeMod = 0;
  int writeData = 0;

  // Write data
  int Reset = 0;
  int SWReady = 0;
  int Exp = 0;
  int Mod = 0;
  int DataIn = 0;

  // Set variables
  int i;
  for(i = 1; i < argc; i++){

    // printf(argv[i]);

    // File path
    if(strcmp("-device", argv[i]) == 0)
    {
      Filename = argv[i+1];
      // printf(Filename);
      i++;
    }
    else if(strcmp("-reset", argv[i]) == 0){
      // Get binary reset value
      Reset = (int)strtol(argv[i+1], &ret, 2);
      i++;
      writeReset = 1;
    }
    else if(strcmp("-ready", argv[i]) == 0){
      // Get binary swready value
      SWReady = (int)strtol(argv[i+1], &ret, 2);
      i++;
      writeReady = 1;
    }
    else if(strcmp("-exp", argv[i]) == 0){
      // Get binary exponent
      Exp = (int)strtol(argv[i+1], &ret, 2);
      i++;
      writeExp = 1;
    }
    else if(strcmp("-mod", argv[i]) == 0){
      // Get binary modulus
      Mod = (int)strtol(argv[i+1], &ret, 2);
      i++;
      writeMod = 1;
    }
    else if(strcmp("-block", argv[i]) == 0){
      // Get binary block
      DataIn = (int)strtol(argv[i+1], &ret, 2);
      i++;
      writeData = 1;
    }

  }


  // Open the dev file for reading (file position default to 0)
  fp = open(Filename, O_WRONLY);
  if(fp < 0){
    return -1;
  }

  // Register 0
  if(writeReset == 1){
    lseek(fp, 0, 0);
    write(fp, &Reset, 4);
    // printf("Write to Reset");
  }

  // Register 1
  if(writeReady == 1){
    lseek(fp, 1, 0);
    write(fp, &SWReady, 4);
    // printf("Write to Ready");
  }

  // Register 2
  if(writeExp == 1){
    lseek(fp, 2, 0);
    write(fp, &Exp, 4);
    // printf("Write to Exp");
  }

  // Register 3
  if(writeMod == 1){
    lseek(fp, 3, 0);
    write(fp, &Mod, 4);
    // printf("Write to Mod");
  }

  // Register 4
  if(writeData == 1){
    lseek(fp, 4, 0);
    write(fp, &DataIn, 4);
    // printf("Write to Data");
  }


  // Print resulting register states
  // print(fp, &(*registers));

  // Close the dev file
  close(fp);

  return 0;
}
