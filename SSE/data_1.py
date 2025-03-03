import random
import string


# Function to generate the index table
def generate_keyword_file_index(num_keywords, num_files):
    index_table = {}

    for _ in range(num_keywords):
        # Randomly generate a keyword (string of 5-10 letters)
        keyword = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))

        # Randomly generate a list of files this keyword maps to (between 1 and 10 files)
        num_assigned_files = random.randint(1, 20)
        files = [f"{random.randint(1, num_files):08d}." for _ in range(num_assigned_files)]

        # Add the keyword and its associated files to the index table
        index_table[keyword] = sorted(set(files))  # Use sorted(set) to avoid duplicate files and sort them

    return index_table


# Generate the index table with custom keyword count and file count
num_keywords = 2000  # Example: 500 keywords
num_files = 500  # Example: 1000 files
index_table = generate_keyword_file_index(num_keywords, num_files)

# Save the index table to a .txt file in the correct format
with open('keyword_file_indexA.txt', 'w') as f:
    f.write("{\n")  # Start of the JSON-like format
    for keyword, files in index_table.items():
        f.write(f'    "{keyword}": [\n')
        for i, file in enumerate(files):
            if i == len(files) - 1:
                f.write(f'        "{file}"\n')  # Last item, no trailing comma
            else:
                f.write(f'        "{file}",\n')
        f.write("    ],\n")
    f.write("}\n")  # End of the JSON-like format

# # 给定二进制字符串 ek
# ek = "0110110011110011010111111101001010011101110110100000111101001011011100101001100101110011101110011110000101111010010111111011010001010000001110000110101100110100100101001000110111011011100111101010001001111100011011000101011000001010110011100011101001100010"
#
# # 将二进制字符串转换为16进制
# hex_value = hex(int(ek, 2))[2:]
#
# # 输出结果
# print(hex_value)
