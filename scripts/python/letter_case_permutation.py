from itertools import product
import sys

def letter_case_permutations(s):
    choices = [(c.lower(), c.upper()) if c.isalpha() else (c,) for c in s] 
    return [''.join(p) for p in product(*choices)]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_string>")
        sys.exit(1)
    input_string = sys.argv[1]        
    if len(input_string) == 0:
        print("Please provide a non-empty string.")
        sys.exit(1)
    else:
        permutations = letter_case_permutations(input_string)
        permutations_string = ""
        for perm in permutations:
            permutations_string += perm + " "
        print (permutations_string.strip())