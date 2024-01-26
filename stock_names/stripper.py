import csv

def main():
    with open('nasdaq_screener.csv', 'r') as data:
        csv_reader = csv.reader(data, delimiter=',')
        counter = 0
        for line in csv_reader:
            if counter < 10:
                print(line)
                counter += 1
            else:
                break

main()