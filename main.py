#print("Hello world!")
msg = "Hello world"
print()
def check_is_digit(input_str):
    """Check if the input string is a valid digit."""
    if input_str.strip().isdigit():
        return True
    else:
        print("Invalid input! Please enter a number.")
        return False
 
while True:
    age_input = input("Enter your age: ").strip()
    if check_is_digit(age_input):  
        age = int(age_input)  
        break  

if age <= 0:
    print("You are a baby")
    print("You are not old enough to drink")
elif 13 <= age <= 18:
    print("You are a teenager")
    if age >= 18:
        print("You are old enough to drink")
    else:
        print("You are not old enough to drink")
else:
    print("You are an adult")
    print("You are old enough to drink")


