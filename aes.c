// NOTE: Almost all the operations in the AES encryption algorithm are done with byte operations, so even though the whole thing is done over a 128-bit input the internals act on bytes only.
// Due to this the key is taken as an array of 16 chars (128 bits) instead of any other combination of data types like array of 2 uint64_t and so on.

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<inttypes.h>

// A check to see if we have 128 bit type available or not
// The check128 variable can be printed to see if we have the type or not
#ifdef __SIZEOF_INT128__
uint8_t const check128 = 1;
#else
uint8_t const check128 = 0;
#endif

// We will define 10 round constants as follows
// These will be needed in performing the key scheduling function implemented afterwards.
const uint32_t Rcon[10] = {
                                // Each individual number in below sequence is a hexadecimal or of 4 bits
    (uint32_t)1 << 24,          // 0100 0000
    (uint32_t)2 << 24,          // 0200 0000
    (uint32_t)4 << 24,          // 0400 0000
    (uint32_t)8 << 24,          // 0800 0000
    (uint32_t)1 << 28,          // 1000 0000
    (uint32_t)2 << 28,          // 2000 0000
    (uint32_t)4 << 28,          // 4000 0000
    (uint32_t)8 << 28,          // 8000 0000
    ((uint32_t)1 << 28) | ((uint32_t)11 << 24),     // 1B00 0000
    ((uint32_t)3 << 28) | ((uint32_t)6 << 24)       // 3600 0000
};

const uint8_t S_BOX[16][16] =  {
                                { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
                                { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
                                { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
                                { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
                                { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
                                { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
                                { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
                                { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
                                { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
                                { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
                                { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
                                { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
                                { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
                                { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
                                { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
                                { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
                            };

const uint8_t INV_S_BOX[16][16] = {
                                { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                                { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                                { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                                { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                                { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                                { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                                { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                                { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                                { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                                { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                                { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                                { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                                { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                                { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                                { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                                { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
                                  };

// A small utility function to print an array of 16, with given indentation(idt) and a message for starting
void print(char *start, uint8_t *arr, char *idt)
{
    printf("%s\n%s", start, idt);
    for (uint8_t  itr = 0; itr < 16; itr++)
        printf("%02X ", arr[itr]);
    printf("\n");
}

// This is the subbytes function which is used in the key scheduling function as well as the encryption algo.
uint8_t subbytes(uint8_t val)
{
    uint8_t row, col;
    uint8_t separator = (1 << 4) - 1;
    col = val & separator;
    val >>= 4;
    row = val & separator;
    return S_BOX[row][col];
}

// The rotword function for the key scheduling algorithm
uint32_t rotword(uint32_t val)
{
    uint32_t separator = UINT8_MAX;
    uint8_t bytes[4];
    uint32_t temp;
    for (uint8_t itr = 0; itr < 4; itr++)
    {
        temp = val & (separator << (8 * itr));
        temp >>= 8 * itr;
        bytes[3 - itr] = temp;
    }
    uint32_t new_val = bytes[0];
    new_val |= (uint32_t)bytes[1] << 24;
    new_val |= (uint32_t)bytes[2] << 16;
    new_val |= (uint32_t)bytes[3] << 8;

    return new_val;
}

// The subword function for the key scheduling algorithm
uint32_t subword(uint32_t val)
{
    uint32_t separator = UINT8_MAX;
    uint8_t bytes[4];
    uint32_t temp;
    for (uint8_t itr = 0; itr < 4; itr++)
    {
        temp = val & (separator << (8 * itr));
        temp >>= 8 * itr;
        bytes[3 - itr] = temp;
    }
    uint8_t new_bytes[4] = {};
    for (uint8_t itr = 0; itr < 4; itr++)
        new_bytes[itr] = subbytes(bytes[itr]);
    uint32_t final_val = new_bytes[3];
    final_val |= ((uint32_t)new_bytes[0]) << 24;
    final_val |= ((uint32_t)new_bytes[1]) << 16;
    final_val |= ((uint32_t)new_bytes[2]) << 8;
    
    return final_val;
}

// This is the key scheduling function of the AES
// Input  : 128 bit key
// Output : 11 round keys, where length of each round key is 128 bit.
// We will generate 44 words denoted by w[0], w[1], w[2], ..., w[43] where size of each word is 32 bit.
// This function will call other functions as well namely ROTWORD and SUBWORD
// Since we do not have a 128 bit unsigned data type in C, we will return a doubly array of 11 x 16 size. We have 11 rows corressponding to 11 keys and 16 bytes in each row to incorporate the 128-bit key.
uint8_t (*key_scheduling_fun(char const *secret_key)) [16]
{
    uint8_t key[16];
    for (uint8_t itr = 0; itr < 16; itr++)
        key[itr] = (uint8_t)secret_key[itr];

    uint32_t words[44] = {};
    for (uint8_t itr = 0; itr < 4; itr++)
        words[itr] = ((uint32_t)key[4*itr] << 24) | ((uint32_t)key[4*itr + 1] << 16) | ((uint32_t)key[4*itr + 2] << 8) | ((uint32_t)key[4*itr + 3]);
    
    uint32_t temp;
    for (uint8_t itr = 4; itr < 44; itr++)
    {
        temp = words[itr - 1];
        if (itr % 4 == 0)
            temp = subword(rotword(temp)) ^ Rcon[(itr / 4) - 1];
        words[itr] = words[itr - 4] ^ temp;
    }
    
    // Since we don't have any 128 bit data type in C so the round keys cannot be formed like w[i] || w[i+1] || w[i+2] || w[i+3]
    // Instead we will store the keys in a doubly array of 11x16
    uint8_t (*round_keys) [16] = calloc(sizeof(uint8_t), 11*16);
    uint8_t word_no;        // This will be used to select the current word on which the operation has to be performed
    for (uint8_t itr = 0; itr < 11; itr++)
    {
        for (uint8_t itr2 = 0; itr2 < 16; itr2++)
        {
            word_no = 4 * itr + itr2 / 4;
            round_keys[itr][itr2] = (uint8_t)(words[word_no] >> ((3 - (itr2 % 4)) * 8));
        }
    }
    return round_keys;
}

// This is a small utility function to evaluate (val * x)mod(x^8 + x^4 + x^3 + x + 1) which is used in mixcolumn approach
uint8_t multiply(uint8_t val)
{
    if (val & 128)
        return (val << 1) ^ 27;
    else
        return val << 1;
}

// This is a small utility function which right shifts an array
void right(uint8_t *arr)
{
    uint8_t temp = arr[3];
    for (uint8_t itr = 3; itr > 0; itr--)
        arr[itr] = arr[itr - 1];
    arr[0] = temp;
}

// This is the implementation of mixcolumn operatior
void mixcolumn(uint8_t *column)
{
    uint8_t temp_column[4];
    for (uint8_t itr = 0; itr < 4; itr++)
        temp_column[itr] = column[itr];
    
    uint8_t mult[] = {1, 2, 0, 0};       // represents {x, x+1, 1, 1} which are used for multiplication
    for (uint8_t itr = 0; itr < 4; itr++)
    {
        uint8_t temp = 0;
        for (uint8_t itr2 = 0; itr2 < 4; itr2++)
        {
            if (mult[itr2] == 0)
                temp ^= temp_column[itr2];
            else if (mult[itr2] == 1)
                temp ^= multiply(temp_column[itr2]);
            else
                temp ^= multiply(temp_column[itr2]) ^ temp_column[itr2];
        }
        // The main thing is here, in mix column
        // first row -  x*t0 + (x+1)*t1 + t2 + t3
        // second row - x*t1 + (x+1)*t2 + t3 + t0 or t0 + x*t1 + (x+1)*t2 + t3
        // On observing we multiplied [x, x+1, 1, 1] for first row and [1, x, x+1, 1] for second row
        // So for each row we right shift the multiplication array by one
        right(mult);
        column[itr] = temp;
    }
}

// This is a small utility function that will swap two values at index1(idx1) and index2(idx2) in the given array(arr)
void swap(uint8_t idx1, uint8_t idx2, uint8_t *arr)
{
    uint8_t temp = arr[idx1];
    arr[idx1] = arr[idx2];
    arr[idx2] = temp;
}

// The plaintext is a char array of 17 bytes with 16 bytes for the message and one for the NULL character.
// Then we have the round keys, they are passed in 8-bit format because all the operations are performed byte wise only.
char* aes(char const *plaintext, uint8_t const (*round_keys) [16])
{
    uint8_t *temp = calloc(sizeof(char), 16);
    for (uint8_t itr = 0; itr < 16; itr++)
        temp[itr] = (uint8_t)plaintext[itr];
    
    // Start here
    printf("\nGenerating the output for the 11 processes\n");
    // 11 rounds loop
    for (uint8_t round = 0; round < 10; round++)
    {
        printf("Round %d\n", round);

        // XORing with round key
        for (uint8_t itr = 0; itr < 16; itr++)
            temp[itr] ^= round_keys[round][itr];
        print("   After XOR with round Key", temp, "\t");
        
        // Subbytes
        for (uint8_t itr = 0; itr < 16; itr++)
            temp[itr] = subbytes(temp[itr]);
        print("   After Subbytes", temp, "\t");

        // Shiftrows
        // Here we will shift each row by its index no. of times so row0 will be shifted 0 times, row2 will be shifted 2 times and so on.
        // So itr is used as the count for shifting
        for (uint8_t itr = 1; itr < 4; itr++)
        {
            // Since the columns are filled up first while filling the 4x4 matrix we have to get the index of the row elements for each row.
            // Example - 
            // Let 16 character input be = "Something Great!"
            // So it will be filled in the 4x4 matrix as shown below
            // -------
            // S t g e
            // o h   a
            // m i G t
            // e n r !
            // -------
            // So indexes in the string for the elements of first(count starting from zero) row are 1,5,9,13 => 1, 4+1, 8+1, 12+1
            // This is what is represented by the row_idx array below
            uint8_t row_idx[4] = {itr, 4 + itr, 8 + itr, 12 + itr};
            // Now we have to left shift the row itr no. of times or simply saying its index no. of times which is done by the following loop
            for(uint8_t itr2 = 1; itr2 <= itr; itr2++)
            {
                // To left shift a row we can simple swap each pair of elements starting from the first pair
                // i.e. swap(0th element and 1st element), the swap(1st element and second element) and so on.
                swap(row_idx[0], row_idx[1], temp);
                swap(row_idx[1], row_idx[2], temp);
                swap(row_idx[2], row_idx[3], temp);
            }
        }
        print("   After Shiftrows", temp, "\t");

        // Mixcolumn
        // A simple check to remove the mixcolumn at round 10 (here round 9 since we started with zero)
        if (round == 9)
            continue;
        for (uint8_t itr = 0; itr < 4; itr++)
        {
            // Here we are passing each column in the array of text
            // first column starts from index 0, second start from index 4 and so on
            // temp is the array of text
            mixcolumn(temp + 4*itr);
        }
        print("   After Mixcolumn", temp, "\t");
    }

    // The output after final XOR with 11th round key
    for (uint8_t itr = 0; itr < 16; itr++)
            temp[itr] ^= round_keys[10][itr];
    print("\n   Final XOR with 11th Key", temp, "\t");
    
    // Just some errands to print correct output
    // Adding NULL character so that the returned character array is printed correctly
    temp = realloc(temp, sizeof(uint8_t) * 17);
    temp[16] = '\0';
    return (char*)temp;
}

// This is a small utility function that multiplies val with x count no. of times
// It is similar to the multiply defined above just with the change that x is multiplied given no. of times
uint8_t multiply_2(uint8_t val, uint8_t count)
{
    uint8_t temp = val;
    for (uint8_t itr = 0; itr < count; itr++)
    {
        if (temp & 128)
            temp = (temp << 1) ^ 27;
        else
            temp <<= 1;
    }
    return temp;
}

uint8_t inverse_subbytes(uint8_t val)
{
    uint8_t row, col;
    uint8_t separator = (1 << 4) - 1;
    col = val & separator;
    val >>= 4;
    row = val & separator;
    return INV_S_BOX[row][col];
}

void inverse_mixcolumn(uint8_t *column)
{
    uint8_t temp_column[4];
    for(uint8_t itr = 0; itr < 4; itr++)
        temp_column[itr] = column[itr];
    
    uint8_t mult[4] = {14, 11, 13, 9};     // These represent the operation to be performed like 14 - x^3 + x^2 + x
    for(uint8_t itr = 0; itr < 4; itr++)
    {
        uint8_t temp = 0;
        for (uint8_t itr2 = 0; itr2 < 4; itr2++)
        {
            if (mult[itr2] == 14)
                temp ^= multiply_2(temp_column[itr2], 3) ^ multiply_2(temp_column[itr2], 2) ^ multiply_2(temp_column[itr2], 1);
            else if (mult[itr2] == 11)
                temp ^= multiply_2(temp_column[itr2], 3) ^ multiply_2(temp_column[itr2], 1) ^ temp_column[itr2];
            else if (mult[itr2] == 13)
                temp ^= multiply_2(temp_column[itr2], 3) ^ multiply_2(temp_column[itr2], 2) ^ temp_column[itr2];
            else
                temp ^= multiply_2(temp_column[itr2], 3) ^ temp_column[itr2];
        }
        column[itr] = temp;
        right(mult);
    }
}

char* aes_decrypt(char const *ciphertext, uint8_t const (*round_keys) [16])
{
    uint8_t *temp = calloc(sizeof(uint8_t), 16);
    for (uint8_t itr = 0; itr < 16; itr++)
        temp[itr] = ciphertext[itr];

    for (uint8_t round = 10; round > 0; round--)
    {
        // Printing round
        printf("Round %d\n", round);

        // XORing with round key
        for(uint8_t itr = 0; itr < 16; itr++)
            temp[itr] ^= round_keys[round][itr];
        print("   After XOR with round key", temp, "\t");

        // Inverse Mixcolumn
        if (round != 10)     // A simple check to avoid mixcolumn for the 10th round (here 9th)
        {
            for (uint8_t itr = 0; itr < 4; itr++)
            {
                // Here we are again passing the head of the column or simply a pointer to the start of column
                // Like column1 starts at index 0, column2 starts at index 4 and so on.
                // Temp is the text array
                inverse_mixcolumn(temp + 4*itr);
            }
            print("   After Inverse Mixcolumn", temp, "\t");
        }

        // Inverse Shiftrows
        // For inversing shiftrows either we could left shift row1 1 time or right shift it 3 times, here I have done the latter
        // The count starts from 0 and we are starting with row 2 because there is no need to shift row1 in any direction
        for (uint8_t itr = 1; itr < 4; itr++)
        {
            // First we calculate the row indexes as calculated in the normal shiftrows
            // The reason for the calculation for row indexes is written in aes function shiftrows part, do check out if not knowing
            uint8_t row_idx[4] = {itr, 4 + itr, 8 + itr, 12 + itr};
            
            // We have to right shift row1 3 times so row(n) by 4 - n times
            for (uint8_t itr2 = 4 - itr; itr2 > 0; itr2--)
            {
                swap(row_idx[0], row_idx[1], temp);
                swap(row_idx[1], row_idx[2], temp);
                swap(row_idx[2], row_idx[3], temp);
            }
        }
        print("   After Inverse Shiftrows", temp, "\t");

        // Inverse Subbytes
        for(uint8_t itr = 0; itr < 16; itr++)
            temp[itr] = inverse_subbytes(temp[itr]);
        print("   After Inverse Subbytes", temp, "\t");
    }

    // Final XOR with 1st key(here 0th key)
    for (uint8_t itr = 0; itr < 16; itr++)
        temp[itr] ^= round_keys[0][itr];
    print("   Final XOR with key", temp, "\t");
    

    // Just some errands to print correct output
    // Adding NULL character so that the returned character array is printed correctly
    temp = realloc(temp, sizeof(uint8_t) * 17);
    temp[16] = '\0';
    return (char*)temp;
}

void main()
{   
    // This line can be uncommented to see if 128 bit is defined in the system or not.
    // Since its not defined in my system it printed zero.
    // printf("%" PRIu8 "\n", check128);

    // Since C doesn't have 128-bit data type, the secret key is first scanned as a string.
    printf("Enter secret key in chars like - \"This is cool\", \nAlso restrict string length to 16\n");
    // Since we cannot have 128bit integers, we will instead divide 128-bit into 16 8-bit parts which are stored in the char array.
    // The array size is 17 to include the NULL character.
    char secret_key[17]; // = "Thats my Kung Fu";
    scanf("%16[^\n]", secret_key);
    printf("Enter plaintext similar to secret_key\n");
    char plaintext[17]; // = "Two One Nine Two";
    scanf(" %16[^\n]", plaintext);
    uint8_t (*round_keys) [16] = key_scheduling_fun(secret_key);
    printf("Round Keys - \n");
    for (uint8_t itr = 0; itr < 11; itr++)
    {
        printf("Round %2d - ",itr);
        for (uint8_t itr2 = 0; itr2 < 16; itr2++)
        {
            printf("%02X ",round_keys[itr][itr2]);
        }
        printf("\n");
    }

    // Encryption       ------------------------------------------------------
    char *ciphertext = aes(plaintext, round_keys);
    print("\nCiphertext", ciphertext, "   ");

    // Decrytpion       ------------------------------------------------------
    char *decrypttext = aes_decrypt(ciphertext, round_keys);

    // Just printing
    print("\nCiphertext", ciphertext, "   ");
    printf("\n\t\t\t OR \n\n");
    printf("\t\t  %s\n",ciphertext);
    print("\nDecrypted text", decrypttext, "   ");
    printf("\n\t\t\t OR \n\n");
    printf("\t\t  %s\n",decrypttext);

    // freeing memory
    free(round_keys);
    free(ciphertext);
    free(decrypttext);
}