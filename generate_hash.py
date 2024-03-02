import hashlib
import os

def generate_hashed_id(user_id):
    salt = os.urandom(16)

    combined = user_id.encode() + salt
    hashed_id = hashlib.sha256(combined).hexdigest()
    return hashed_id, salt.hex()

def main():
    for i in range(1, 3): 
        user_id = f"user{i}"
        hashed_id, salt = generate_hashed_id(user_id)
        print(f"Original ID: {user_id} -> Hashed ID: {hashed_id} with Salt: {salt}")

if __name__ == "__main__":
    main()
