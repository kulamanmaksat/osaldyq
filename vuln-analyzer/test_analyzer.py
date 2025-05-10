import app

def analyze_file(filename):
    print(f"\nАнализ файла {filename}:")
    print("-" * 50)
    
    with open(f'test_samples/{filename}', 'r') as f:
        result = app.analyze_code(f.read())
        
    print(f'Оценка уязвимости: {result["score"]}%')
    print(f'Уровень риска: {result["risk"]}')
    print(f'Найдено уязвимостей: {result["found_vulnerabilities"]} из {result["total_checks"]}')
    
    if result["vulnerabilities"]:
        print('\nОбнаруженные уязвимости:')
        for vuln in result["vulnerabilities"]:
            print(f'- {vuln}')
    else:
        print('\nУязвимостей не обнаружено')
    print("-" * 50)

# Анализируем все тестовые файлы
test_files = [
    'multiple_vulnerabilities.py',
    'race_condition.py',
    'buffer_overflow.py',
    'secure_code.py'
]

for file in test_files:
    analyze_file(file) 