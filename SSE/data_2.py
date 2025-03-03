import random
import string


# Function to generate the index table
def generate_keyword_file_index(num_keywords, num_files):
    index_table = {}

    for _ in range(num_keywords):
        keyword = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))

        files = [f"{i:08d}." for i in range(num_files)]

        # Add the keyword and its associated files to the index table
        index_table[keyword] = sorted(set(files))  # Use sorted(set) to avoid duplicate files and sort them

    return index_table


# Generate the index table with custom keyword count and file count
num_files = 1000
num_keywords = 1000
index_table = generate_keyword_file_index(num_keywords, num_files)

# Save the index table to a .txt file in the correct format
with open('keyword_file_indexB.txt', 'w') as f:
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
