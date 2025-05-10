import time

class BankAccount:
    def __init__(self):
        self.balance = 1000

    def withdraw(self, amount):
        # Race condition vulnerability
        current_balance = self.balance
        if current_balance >= amount:
            # Simulating some delay
            time.sleep(0.1)
            self.balance = current_balance - amount
            return True
        return False

    def deposit(self, amount):
        current_balance = self.balance
        # Simulating some delay
        time.sleep(0.1)
        self.balance = current_balance + amount 