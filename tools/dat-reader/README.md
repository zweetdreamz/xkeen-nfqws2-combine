# Xray/V2Ray `.dat` reader

`dat_reader.py` показывает, какие категории и доменные правила находятся в
бинарных базах Xray/V2Ray (`geosite.dat`, `zkeen.dat`,
`geosite_v2fly.dat`). Внешние Python-пакеты не нужны.

## Быстрый старт

Из корня проекта:

```powershell
python tools/dat-reader/dat_reader.py C:\path\to\zkeen.dat
```

Без дополнительных флагов выводятся все категории и число доменов в каждой:

```text
C:\path\to\zkeen.dat  geosite  categories=2 domains=42
  discord       30
  youtube       12
```

Показать домены определённой категории:

```powershell
python tools/dat-reader/dat_reader.py C:\path\to\zkeen.dat --category youtube
```

Показать вообще все домены:

```powershell
python tools/dat-reader/dat_reader.py C:\path\to\*.dat --domains
```

Найти текст во всех сохранённых правилах нескольких баз:

```powershell
python tools/dat-reader/dat_reader.py C:\path\to\*.dat --search discord
```

Проверить, в каких файлах и категориях есть правило, реально совпадающее с
доменом по семантике Xray (`plain`, `regex`, `domain`, `full`):

```powershell
python tools/dat-reader/dat_reader.py C:\path\to\*.dat --match cdn.discordapp.com
```

Можно передать каталог: все `.dat` внутри него будут найдены рекурсивно.
Для обработки результата скриптом добавьте `--json`.

Файл с роутера можно разобрать без сохранения локальной копии:

```powershell
ssh root@192.168.1.1 "cat /opt/etc/xray/dat/geosite_refilter.dat" |
  python tools/dat-reader/dat_reader.py -
```

`geoip.dat` и `zkeenip.dat` распознаются отдельно. Для них reader выводит
категории и число IP-сетей и явно отмечает, что доменных правил в базе нет.

## Формат строк с доменами

Столбцы разделены табуляцией:

```text
файл    категория    тип_правила    значение    @атрибуты
```

Типы правил:

- `plain` — значение встречается внутри имени хоста;
- `regex` — регулярное выражение;
- `domain` — домен и любые его поддомены;
- `full` — только точное имя хоста.
