 ## <i> AES-Implementation </i>
 ### 🏗️ About:
 This is a full-fledged implementation of the Advanced Encryption Standard cipher. Code is written in C using inttypes (mainly unint_8). I have tried to add as many comments as possible for a detailed explaination of the code.
 
 ### 📄 Algorithm:
 #### Key-Scheduling
 The input is a  128-bit key which then generates 11 round keys.
 #### Subbytes
 The plaintext is then operated on using the subbytes look up into the table.
 #### Mixcolumns
 The toughest of all, it takes 4x4 matrix of 128 and generates a totally pseudorandom matrix
