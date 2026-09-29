# -*- coding: utf-8 -*-
"""
Сбер POS / POS-Center OS — сервер кассы (Flask) для Amvera.
Домен: https://tel-charger7772585.amvera.io
Хранилище: авто-поиск writable-папки (DATA_DIR env -> папка проекта -> cwd -> /tmp),
иначе RAM-режим. Резервные копии: /api/backup и /api/restore.
"""
import json, os, socket, tempfile, threading, time, uuid, zlib
from datetime import datetime
from flask import Flask, request, jsonify, Response

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEY = b'Sb3rP0sK3y2024!!'
IV  = b'IvSb3rP0s2024!!!'
PROMOS = {'VESNA2026': 15, 'SBER10': 10, 'SALE5': 5}
BONUS_MAX_PERCENT = 80
SNACK = 'Сладости и Снеки'
LOCK = threading.Lock()

_env_srv = os.environ.get('SERVER_URL', '').strip()
SRV = _env_srv if _env_srv.startswith('http') else 'https://tel-charger7772585.amvera.io'

# ================= ВЫБОР ПАПКИ ДЛЯ ДАННЫХ (Amvera: FS может быть read-only) =================
def _pick_data_dir():
    cands = []
    env = os.environ.get('DATA_DIR', '').strip()
    if env: cands.append(env)
    cands += [APP_DIR, os.getcwd(), '/tmp', tempfile.gettempdir()]
    for d in cands:
        if not d: continue
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, '.sber_write_test')
            with open(probe, 'w', encoding='utf-8') as f: f.write('1')
            os.remove(probe)
            return d
        except Exception:
            continue
    return None

DATA_DIR = _pick_data_dir()
DATA_FILE = os.path.join(DATA_DIR, 'sberpos_data.json') if DATA_DIR else None
STORAGE_MODE = 'file' if DATA_FILE else 'ram'

# ================= PURE-PYTHON AES-128-CBC =================
SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def _xt(b): return ((b << 1) ^ (0x1b if b & 0x80 else 0)) & 0xff
def _key_exp(key):
    w = [list(key[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i-1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]; t = [SBOX[b] for b in t]; t[0] ^= RCON[i//4 - 1]
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return w
def _enc_block(bl, w):
    s = bl[:]
    for c in range(4):
        for r in range(4): s[r+4*c] ^= w[c][r]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]; t = s[:]
        for r in range(4):
            for c in range(4): s[r+4*c] = t[r+4*((c+r) % 4)]
        if rnd != 10:
            for c in range(4):
                a0,a1,a2,a3 = s[4*c],s[4*c+1],s[4*c+2],s[4*c+3]; x = a0^a1^a2^a3
                s[4*c]=a0^x^_xt(a0^a1); s[4*c+1]=a1^x^_xt(a1^a2); s[4*c+2]=a2^x^_xt(a2^a3); s[4*c+3]=a3^x^_xt(a3^a0)
        for c in range(4):
            for r in range(4): s[r+4*c] ^= w[rnd*4+c][r]
    return s
def aes_hex(data: bytes) -> str:
    pad = 16 - (len(data) % 16); data = data + bytes([pad])*pad
    w = _key_exp(KEY); prev = list(IV); out = bytearray()
    for off in range(0, len(data), 16):
        blk = [data[off+i] ^ prev[i] for i in range(16)]
        enc = _enc_block(blk, w); out += bytes(enc); prev = enc
    return out.hex()
def enc_payload(obj) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    return aes_hex(zlib.compress(raw.encode('utf-8')))

# ================= БАЗА 100 ТОВАРОВ =================
BASE = [
(1,'Рис Круглозерный 900г','101','460123450001',110,45,'шт','Бакалея'),(2,'Гречневая крупа Ядрица 900г','102','460123450002',85,60,'шт','Бакалея'),(3,'Макароны Рожки Макфа 450г','103','460123450003',62,80,'шт','Бакалея'),(4,'Сахар-песок 1кг','104','460123450004',68,120,'шт','Бакалея'),(5,'Соль поваренная пищевая 1кг','105','460123450005',24,150,'шт','Бакалея'),(6,'Мука Пшеничная в/с 2кг','106','460123450006',125,40,'шт','Бакалея'),(7,'Масло подсолнечное Олейна 1л','107','460123450007',135,55,'шт','Бакалея'),(8,'Масло оливковое Extra Virgin 500мл','108','460123450008',690,18,'шт','Бакалея'),(9,'Хлопья Овсяные Геркулес 400г','109','460123450009',58,70,'шт','Бакалея'),(10,'Горох шлифованный желтый 800г','110','460123450010',49,50,'шт','Бакалея'),
(11,'Молоко 3.2% Простоквашино 930мл','201','460123450011',98,65,'шт','Молочные продукты'),(12,'Творог 9% Домик в деревне 180г','202','460123450012',115,35,'шт','Молочные продукты'),(13,'Сметана 20% Ростагроэкспорт 300г','203','460123450013',125,40,'шт','Молочные продукты'),(14,'Сыр Российский 45% премиум','204','460123450014',740,25,'кг','Молочные продукты'),(15,'Масло Сливочное 82.5% ГОСТ 180г','205','460123450015',195,50,'шт','Молочные продукты'),(16,'Йогурт питьевой Клубника 290г','206','460123450016',65,80,'шт','Молочные продукты'),(17,'Кефир 2.5% Домик в деревне 900мл','207','460123450017',92,30,'шт','Молочные продукты'),(18,'Ряженка 4% Брест-Литовск 450г','208','460123450018',74,28,'шт','Молочные продукты'),(19,'Сыр Моцарелла для пиццы 200г','209','460123450019',185,20,'шт','Молочные продукты'),(20,'Сгущенное молоко Рогачев 380г','210','460123450020',140,90,'шт','Молочные продукты'),
(21,'Сок Яблочный Добрый 1л','301','460123450021',129,60,'шт','Напитки'),(22,'Сок Апельсиновый RICH 1л','302','460123450022',179,45,'шт','Напитки'),(23,'Вода Минеральная Боржоми 0.5л','303','460123450023',95,100,'шт','Напитки'),(24,'Кола Черноголовка 1.5л','304','460123450024',110,75,'шт','Напитки'),(25,'Лимонад Байкал 1л','305','460123450025',88,50,'шт','Напитки'),(26,'Кофе растворимый Nescafe 95г','306','460123450026',340,30,'шт','Напитки'),(27,'Чай Черный Greenfield 25 пак','307','460123450027',145,85,'шт','Напитки'),(28,'Энергетик Adrenaline 0.44л','308','460123450028',139,40,'шт','Напитки'),(29,'Квас Русский Никола 1.5л','309','460123450029',99,35,'шт','Напитки'),(30,'Морс Брусничный Клюквенный 1л','310','460123450030',135,25,'шт','Напитки'),
(31,'Хлеб Нарезной Бородино 400г','401','460123450031',48,50,'шт','Выпечка и Хлеб'),(32,'Батон Нарезной в/с 350г','402','460123450032',42,65,'шт','Выпечка и Хлеб'),(33,'Лаваш Армянский тонкий 200г','403','460123450033',55,30,'шт','Выпечка и Хлеб'),(34,'Круассан с шоколадом 80г','404','460123450034',89,20,'шт','Выпечка и Хлеб'),(35,'Булочка с корицей Синнабон 100г','405','460123450035',65,25,'шт','Выпечка и Хлеб'),(36,'Плетенка с маком 150г','406','460123450036',72,15,'шт','Выпечка и Хлеб'),(37,'Багет Французский хрустящий 250г','407','460123450037',68,18,'шт','Выпечка и Хлеб'),(38,'Сухарики Ржаные с чесноком 80г','408','460123450038',38,110,'шт','Выпечка и Хлеб'),(39,'Пирожок с яблоком 90г','409','460123450039',45,40,'шт','Выпечка и Хлеб'),(40,'Сушки Простые 200г','410','460123450040',59,45,'шт','Выпечка и Хлеб'),
(41,'Яблоки Семеренко свежие','501','460123450041',135,80,'кг','Овощи и Фрукты'),(42,'Бананы спелые Эквадор','502','460123450042',149,95,'кг','Овощи и Фрукты'),(43,'Томаты Тепличные красные','503','460123450043',220,40,'кг','Овощи и Фрукты'),(44,'Огурцы Короткоплодные','504','460123450044',180,35,'кг','Овощи и Фрукты'),(45,'Картофель молодой сетка 3кг','505','460123450045',165,50,'шт','Овощи и Фрукты'),(46,'Лук репчатый отборный','506','460123450046',42,120,'кг','Овощи и Фрукты'),(47,'Морковь мытая свежая','507','460123450047',48,90,'кг','Овощи и Фрукты'),(48,'Лимоны свежие импорт','508','460123450048',190,30,'кг','Овощи и Фрукты'),(49,'Апельсины сочные Египет','509','460123450049',160,65,'кг','Овощи и Фрукты'),(50,'Виноград Кишмиш без косточки','510','460123450050',280,25,'кг','Овощи и Фрукты'),
(51,'Пельмени Сибирские отборные 800г','601','460123450051',450,30,'шт','Заморозка'),(52,'Вареники с картофелем и грибами 450г','602','460123450052',190,40,'шт','Заморозка'),(53,'Пицца Пепперони замороженная 350г','603','460123450053',299,25,'шт','Заморозка'),(54,'Овощная смесь Мексиканская 400г','604','460123450054',145,55,'шт','Заморозка'),(55,'Мороженое Пломбир Ванильный 450г','605','460123450055',280,35,'шт','Заморозка'),(56,'Рыбные палочки тресковые 300г','606','460123450056',210,20,'шт','Заморозка'),(57,'Блинчики с мясом С пылу с жару 360г','607','460123450057',175,38,'шт','Заморозка'),(58,'Котлеты Домашние замороженные 400г','608','460123450058',240,28,'шт','Заморозка'),(59,'Креветки королевские 500г','609','460123450059',890,15,'шт','Заморозка'),(60,'Ягоды замороженные Клубника 300г','610','460123450060',199,22,'шт','Заморозка'),
(61,'Колбаса Докторская ГОСТ Клинский','701','460123450061',425,35,'шт','Мясо и Колбасы'),(62,'Сосиски Молочные Велком 440г','702','460123450062',349,45,'шт','Мясо и Колбасы'),(63,'Говядина мраморная Рибай охлажденная','703','460123450063',2575,12,'кг','Мясо и Колбасы'),(64,'Сервелат Коньячный Черкизово','704','460123450064',580,20,'кг','Мясо и Колбасы'),(65,'Филе Куриное охл. Петелинка','705','460123450065',390,50,'кг','Мясо и Колбасы'),(66,'Ветчина Рубленная сытная 400г','706','460123450066',295,30,'шт','Мясо и Колбасы'),(67,'Бекон сырокопченый нарезка 150г','707','460123450067',189,40,'шт','Мясо и Колбасы'),(68,'Шашлык свиной в маринаде 1кг','708','460123450068',490,22,'кг','Мясо и Колбасы'),(69,'Стейк из лосося охлажденный','709','460123450069',1890,8,'кг','Мясо и Колбасы'),(70,'Паштет печеночный премиум 150г','710','460123450070',110,60,'шт','Мясо и Колбасы'),
(71,'Мыло жидкое Palmolive 300мл','801','460123450071',199,50,'шт','Бытовая химия'),(72,'Салфетки бумажные Zewa 100шт','802','460123450072',110,90,'шт','Бытовая химия'),(73,'Средство Fairy Лимон 450мл','803','460123450073',165,70,'шт','Бытовая химия'),(74,'Порошок стиральный Ariel 3кг','804','460123450074',690,25,'шт','Бытовая химия'),(75,'Зубная паста Colgate Тотал 75мл','805','460123450075',185,60,'шт','Бытовая химия'),(76,'Шампунь Head&Shoulders 400мл','806','460123450076',390,35,'шт','Бытовая химия'),(77,'Губки для посуды профи 5шт','807','460123450077',59,110,'шт','Бытовая химия'),(78,'Пакеты для мусора 60л 20шт','808','460123450078',89,85,'шт','Бытовая химия'),(79,'Чистящий крем Cif 500мл','809','460123450079',230,40,'шт','Бытовая химия'),(80,'Освежитель воздуха AirWick 250мл','810','460123450080',279,30,'шт','Бытовая химия'),
(81,'Шоколад Алёнка Молочный 100г','901','460123450081',115,95,'шт','Сладости и Снеки'),(82,'Конфеты Мишка Косолапый 250г','902','460123450082',290,40,'шт','Сладости и Снеки'),(83,'Печенье Овсяное классическое 300г','903','460123450083',85,75,'шт','Сладости и Снеки'),(84,'Зефир Ванильный в шоколаде 250г','904','460123450084',140,35,'шт','Сладости и Снеки'),(85,'Вафли Шоколадные Яшкино 200г','905','460123450085',68,80,'шт','Сладости и Снеки'),(86,'Чипсы Lays Сметана и зелень 140г','906','460123450086',149,100,'шт','Сладости и Снеки'),(87,'Орешки кешью жареные 100г','907','460123450087',199,45,'шт','Сладости и Снеки'),(88,'Мармелад жевательный Haribo 100г','908','460123450088',110,65,'шт','Сладости и Снеки'),(89,'Рулет бисквитный Шоколадный 200г','909','460123450089',79,50,'шт','Сладости и Снеки'),(90,'Попкорн карамельный 150г','910','460123450090',95,40,'шт','Сладости и Снеки'),
(91,'Зубочистки Интерпрофи 250шт','18','4600741290015',9,200,'шт','Хозтовары'),(92,'Пакет Майка фирменный POS CENTER','01','460123450092',8,500,'шт','Хозтовары'),(93,'Батарейки АА Duracell 4шт','02','460123450093',380,60,'шт','Хозтовары'),(94,'Пленка пищевая кулинарная 30м','03','460123450094',75,40,'шт','Хозтовары'),(95,'Фольга алюминиевая 10м','04','460123450095',115,35,'шт','Хозтовары'),(96,'Свечи хозяйственные 4шт','05','460123450096',130,25,'шт','Хозтовары'),(97,'Скотч прозрачный широкий 50м','06','460123450097',98,50,'шт','Хозтовары'),(98,'Зажигалка газовая стандарт','07','460123450098',45,150,'шт','Хозтовары'),(99,'Спички кухонные 10 коробков','08','460123450099',35,180,'шт','Хозтовары'),(100,'Перчатки латексные хозяйственные L','09','460123450100',89,70,'шт','Хозтовары')]

def default_data():
    return {
        'products': [dict(id=a, name=b, code=c, barcode=d, price=float(e), stock=f, unit=g, category=h) for (a,b,c,d,e,f,g,h) in BASE],
        'clients': [
            {'phone':'79991234567','name':'Иван Петров','bonus':500,'spent':6200},
            {'phone':'79161112233','name':'Мария Сидорова','bonus':120,'spent':1500},
            {'phone':'79035556677','name':'Олег Козлов','bonus':980,'spent':24000}],
        'wallets': {},
        'receipts': [], 'returns': [], 'sessions': {},
        'stats': {'revenue':0,'checks':0,'sberPay':0,'wallet':0,'card':0,'cash':0,'drawer':0,'returnsSum':0},
        'checkNo': 1001, 'shiftNo': 14,
        'settings': {'storeName':'ООО СБЕР МАРКЕТ #42','inn':'770123456789','cashier':'Администратор (Смена №14)'}}

def load():
    d = None
    if DATA_FILE and os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f: d = json.load(f)
        except Exception: d = None
    if not d: d = default_data()
    d.setdefault('wallets', {})
    d.setdefault('clients', [])
    d.setdefault('stats', {}).setdefault('wallet', 0)
    return d
DATA = load()

# ============ СОХРАНЕНИЕ: продукты первыми, секции через пустую строку ============
SECTION_ORDER = ['products','clients','wallets','receipts','returns','sessions','stats','checkNo','shiftNo','settings']
def save():
    if not DATA_FILE:
        return False  # RAM-режим: писать некуда, работаем без падений
    ordered = {}
    for k in SECTION_ORDER:
        if k in DATA: ordered[k] = DATA[k]
    for k in DATA:
        if k not in ordered: ordered[k] = DATA[k]
    text = json.dumps(ordered, ensure_ascii=False, indent=2)
    for k in SECTION_ORDER[1:]:
        text = text.replace('\n  "%s":' % k, '\n\n  "%s":' % k)
    try:
        tmp = DATA_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f: f.write(text)
        os.replace(tmp, DATA_FILE)
        return True
    except Exception as e:
        print('[save] ошибка записи: %s' % e)
        return False
def time_ms(): return int(time.time()*1000)
def today_str(): return datetime.now().strftime('%Y-%m-%d')

# ================= ЛОЯЛЬНОСТЬ + КОШЕЛЁК =================
def level_name(c):
    if c.get('level'): return str(c['level'])
    return 'Золотой' if c['spent'] >= 20000 else ('Серебряный' if c['spent'] >= 5000 else 'Новый')
def level_pct(c):
    if c.get('pct') is not None:
        try: return max(0, min(100, int(c['pct'])))
        except Exception: pass
    return 10 if c['spent'] >= 20000 else (7 if c['spent'] >= 5000 else 5)
def write_pct(c):
    if c.get('write_pct') is not None:
        try: return max(0, min(100, int(c['write_pct'])))
        except Exception: pass
    return BONUS_MAX_PERCENT
def find_client(phone):
    if not phone: return None
    for c in DATA['clients']:
        if c['phone'] == phone: return c
    return None
def register_client(phone):
    c = {'phone': phone, 'name': 'Клиент ' + phone[-4:], 'bonus': 100, 'spent': 0}
    DATA['clients'].append(c); save()
    return c
def ensure_wallet(phone):
    w = DATA['wallets'].get(phone)
    if w is None:
        w = {'balance': 0.0, 'lastTopup': ''}
        DATA['wallets'][phone] = w
    if w.get('lastTopup') != today_str():
        w['balance'] = round(w['balance'] + 10000.0, 2)
        w['lastTopup'] = today_str()
    return w
def price_cart(items, client, promo, write):
    subtotal = 0.0; happy = 0.0
    hour = datetime.now().hour
    for it in items:
        p = next((x for x in DATA['products'] if x['id'] == it['id']), None)
        if not p: continue
        s = p['price'] * it['qty']; subtotal += s
        if hour >= 20 and p['category'] == SNACK: happy += s * 0.2
    after = subtotal - happy
    pd = after * (PROMOS.get(promo, 0) / 100.0) if promo in PROMOS else 0.0
    after2 = after - pd
    sd = after2 * 0.05 if after2 >= 1000 else 0.0
    payable_raw = after2 - sd
    max_write = int(min(client['bonus'], payable_raw * write_pct(client) / 100.0)) if client else 0
    write = int(min(write or 0, max_write))
    payable = payable_raw - write
    pct = level_pct(client) if client else 0
    accrual = int(round(payable * pct / 100.0)) if client else 0
    return dict(subtotal=round(subtotal,2), happy=round(happy,2), promoDisc=round(pd,2), sumDisc=round(sd,2),
                discountTotal=round(happy+pd+sd,2), write=write, maxWrite=max_write, payable=round(payable,2),
                accrual=accrual, pct=pct, level=level_name(client) if client else None)

app = Flask(__name__)
try: app.json.ensure_ascii = False
except Exception: app.config['JSON_AS_ASCII'] = False

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/')
def index(): return Response(HTML, mimetype='text/html')

@app.route('/api/health')
def api_health():
    return jsonify(mode=STORAGE_MODE, data_dir=DATA_DIR, data_file=DATA_FILE,
                   writable=bool(DATA_DIR), srv=SRV,
                   products=len(DATA['products']), clients=len(DATA['clients']),
                   wallets=len(DATA['wallets']), receipts=len(DATA['receipts']))

@app.route('/api/backup')
def api_backup():
    text = json.dumps(DATA, ensure_ascii=False, indent=2)
    r = Response(text, mimetype='application/json')
    r.headers['Content-Disposition'] = 'attachment; filename=sberpos_data.json'
    return r

@app.route('/api/restore', methods=['POST'])
def api_restore():
    global DATA
    d = request.get_json(force=True, silent=True)
    if not isinstance(d, dict) or 'products' not in d:
        return jsonify(error='bad backup'), 400
    with LOCK:
        base = default_data()
        for k in ['clients','wallets','receipts','returns','sessions','stats','settings','checkNo','shiftNo']:
            d.setdefault(k, base[k])
        d['stats'].setdefault('wallet', 0)
        DATA = d
        ok = save()
    return jsonify(ok=True, saved=ok)

@app.route('/api/state')
def api_state():
    return jsonify(products=DATA['products'], receipts=DATA['receipts'], returns=DATA['returns'],
                   stats=DATA['stats'], checkNo=DATA['checkNo'], shiftNo=DATA['shiftNo'],
                   settings=DATA['settings'], srv=SRV, storage=STORAGE_MODE)

@app.route('/api/client')
def api_client():
    phone = request.args.get('phone', '')
    with LOCK:
        c = find_client(phone); created = False
        if not c and phone.isdigit() and len(phone) >= 10:
            c = register_client(phone); created = True
        if not c: return jsonify(found=False)
        w = ensure_wallet(phone); save()
        return jsonify(found=True, created=created, client=c, level=level_name(c), pct=level_pct(c),
                       wallet=w['balance'], walletTopup=w['lastTopup'])

@app.route('/api/wallet')
def api_wallet():
    phone = request.args.get('phone', '')
    if not (phone.isdigit() and len(phone) >= 10): return jsonify(found=False)
    with LOCK:
        w = ensure_wallet(phone)
        c = find_client(phone)
        save()
        return jsonify(found=True, phone=phone, balance=w['balance'], lastTopup=w['lastTopup'],
                       name=c['name'] if c else 'Карта ' + phone[-4:],
                       bonus=c['bonus'] if c else 0,
                       level=level_name(c) if c else 'Новый',
                       pct=level_pct(c) if c else 5)

@app.route('/api/wallet/pay', methods=['POST'])
def wallet_pay():
    d = request.get_json(force=True)
    phone = (d.get('phone') or '').strip()
    with LOCK:
        s = DATA['sessions'].get(d.get('sid', ''))
        if not s: return jsonify(error='no session'), 404
        if s['status'] == 'done': return jsonify(ok=True, receipt=s['receipt'])
        if not (phone.isdigit() and len(phone) >= 10): return jsonify(error='phone'), 400
        w = ensure_wallet(phone)
        pr = s['pricing']
        if w['balance'] + 1e-9 < pr['payable']:
            save()
            return jsonify(error='insufficient', balance=w['balance']), 402
        w['balance'] = round(w['balance'] - pr['payable'], 2)
        num = str(DATA['checkNo']).zfill(5)
        client = find_client(s['clientPhone']) or find_client(phone)
        nb = None
        if client:
            client['bonus'] = client['bonus'] - pr['write'] + pr['accrual']
            client['spent'] += pr['payable']; nb = client['bonus']
        for it in s['items']:
            p = next(x for x in DATA['products'] if x['id'] == it['id'])
            p['stock'] = max(0, p['stock'] - it['qty'])
        st = DATA['stats']
        st['revenue'] += pr['payable']; st['checks'] += 1
        st['wallet'] = st.get('wallet', 0) + pr['payable']
        pay_label = 'Карта телефона'
        dt_str = datetime.now().strftime('%d.%m.%Y %H:%M')
        receipt = dict(num=num, ts=time_ms(), dateTime=dt_str,
                       items=[dict(name=i['name'], qty=i['qty'], price=i['price']) for i in s['items']],
                       subtotal=pr['subtotal'], total=pr['payable'], vat=round(pr['payable']*20/120, 2),
                       discount=pr['discountTotal'], promo=s['promo'], write=pr['write'], accrual=pr['accrual'],
                       clientPhone=phone, nb=nb, walletPhone=phone, payType=pay_label,
                       fd=str(uuid.uuid4().int)[:9], fp=str(uuid.uuid4().int)[:10])
        rp = dict(n=num, mode='view', pt=pay_label, dt=dt_str,
                  t=int(round(pr['payable']*100)), i=[dict(m=i['name'][:14], q=i['qty']) for i in s['items']])
        if pr['discountTotal'] > 0: rp['d'] = int(round(pr['discountTotal']*100))
        if s['promo']: rp['pc'] = s['promo']
        if client: rp.update(c=client['phone'], w=pr['write'], b=pr['accrual'], nb=nb, cs=client['spent'])
        receipt['code'] = enc_payload(rp)
        DATA['receipts'].insert(0, receipt); DATA['receipts'] = DATA['receipts'][:200]
        DATA['checkNo'] += 1
        s['status'] = 'done'; s['receipt'] = receipt
        save()
        return jsonify(ok=True, receipt=receipt, balance=w['balance'])

@app.route('/api/card')
def api_card():
    phone = request.args.get('phone', '')
    with LOCK:
        c = find_client(phone)
        if not c and phone.isdigit() and len(phone) >= 10:
            c = register_client(phone)
        if not c: return jsonify(found=False)
        w = ensure_wallet(phone); save()
        hist = []
        for r in DATA['receipts']:
            if r.get('clientPhone') == phone and r.get('accrual') is not None:
                hist.append('Чек №%s: +%s б / −%s б' % (r['num'], r.get('accrual',0), r.get('write',0)))
            if len(hist) >= 5: break
        return jsonify(found=True, phone=c['phone'], bonus=c['bonus'], spent=c['spent'],
                       level=level_name(c), pct=level_pct(c), hist='\n'.join(hist),
                       wallet=w['balance'], walletTopup=w['lastTopup'])

@app.route('/api/session/start', methods=['POST'])
def session_start():
    d = request.get_json(force=True)
    items = [i for i in d.get('items', []) if next((x for x in DATA['products'] if x['id'] == i['id']), None)]
    if not items: return jsonify(error='empty'), 400
    client = find_client(d.get('clientPhone'))
    pr = price_cart(items, client, d.get('promo'), d.get('write'))
    sid = uuid.uuid4().hex[:12]
    snap = []
    for it in items:
        p = next(x for x in DATA['products'] if x['id'] == it['id'])
        snap.append(dict(id=p['id'], name=p['name'], price=p['price'], qty=it['qty']))
    nb = client['bonus'] - pr['write'] + pr['accrual'] if client else None
    payload = dict(sid=sid, srv=SRV, mode='pay', n=str(DATA['checkNo']).zfill(5),
                   t=int(round(pr['payable']*100)), i=[dict(m=s['name'][:14], q=s['qty']) for s in snap])
    if pr['discountTotal'] > 0: payload['d'] = int(round(pr['discountTotal']*100))
    if d.get('promo') in PROMOS: payload['pc'] = d['promo']
    if client: payload.update(c=client['phone'], w=pr['write'], b=pr['accrual'], nb=nb, cs=client['spent']+pr['payable'])
    with LOCK:
        DATA['sessions'][sid] = dict(sid=sid, items=snap, pricing=pr, clientPhone=client['phone'] if client else None,
                                     promo=d.get('promo'), status='wait', ts=time_ms())
        save()
    return jsonify(sid=sid, code=enc_payload(payload), pricing=pr)

@app.route('/api/session/status')
def session_status():
    s = DATA['sessions'].get(request.args.get('sid', ''))
    if not s: return jsonify(status='none')
    return jsonify(status=s['status'], receipt=s.get('receipt'))

@app.route('/api/session/confirm', methods=['POST'])
def session_confirm():
    d = request.get_json(force=True)
    with LOCK:
        s = DATA['sessions'].get(d.get('sid', ''))
        if not s: return jsonify(error='no session'), 404
        if s['status'] == 'done': return jsonify(ok=True, receipt=s['receipt'])
        pr = s['pricing']
        num = str(DATA['checkNo']).zfill(5)
        client = find_client(s['clientPhone']); nb = None
        if client:
            client['bonus'] = client['bonus'] - pr['write'] + pr['accrual']
            client['spent'] += pr['payable']; nb = client['bonus']
        for it in s['items']:
            p = next(x for x in DATA['products'] if x['id'] == it['id'])
            p['stock'] = max(0, p['stock'] - it['qty'])
        st = DATA['stats']
        st['revenue'] += pr['payable']; st['checks'] += 1; st['sberPay'] += pr['payable']
        pay_label = 'СберPay (QR)'
        dt_str = datetime.now().strftime('%d.%m.%Y %H:%M')
        receipt = dict(num=num, ts=time_ms(), dateTime=dt_str,
                       items=[dict(name=i['name'], qty=i['qty'], price=i['price']) for i in s['items']],
                       subtotal=pr['subtotal'], total=pr['payable'], vat=round(pr['payable']*20/120, 2),
                       discount=pr['discountTotal'], promo=s['promo'], write=pr['write'], accrual=pr['accrual'],
                       clientPhone=s['clientPhone'], nb=nb, payType=pay_label,
                       fd=str(uuid.uuid4().int)[:9], fp=str(uuid.uuid4().int)[:10])
        rp = dict(n=num, mode='view', pt=pay_label, dt=dt_str,
                  t=int(round(pr['payable']*100)), i=[dict(m=i['name'][:14], q=i['qty']) for i in s['items']])
        if pr['discountTotal'] > 0: rp['d'] = int(round(pr['discountTotal']*100))
        if s['promo']: rp['pc'] = s['promo']
        if client: rp.update(c=client['phone'], w=pr['write'], b=pr['accrual'], nb=nb, cs=client['spent'])
        receipt['code'] = enc_payload(rp)
        DATA['receipts'].insert(0, receipt); DATA['receipts'] = DATA['receipts'][:200]
        DATA['checkNo'] += 1
        s['status'] = 'done'; s['receipt'] = receipt
        save()
        return jsonify(ok=True, receipt=receipt)

@app.route('/api/product', methods=['POST'])
def product_add():
    d = request.get_json(force=True)
    with LOCK:
        nid = max([p['id'] for p in DATA['products']] + [0]) + 1
        DATA['products'].append(dict(id=nid, name=d['name'], code=d['code'], barcode=d['barcode'],
                                     price=float(d['price']), stock=int(d.get('stock', 0)),
                                     unit=d.get('unit','шт'), category=d.get('category','Бакалея')))
        save()
    return jsonify(ok=True, id=nid)

@app.route('/api/product/update', methods=['POST'])
def product_update():
    d = request.get_json(force=True)
    with LOCK:
        p = next((x for x in DATA['products'] if x['id'] == d['id']), None)
        if not p: return jsonify(error='nf'), 404
        if 'price' in d: p['price'] = round(float(d['price']), 2)
        if 'stock' in d: p['stock'] = max(0, int(d['stock']))
        save()
    return jsonify(ok=True)

@app.route('/api/restock_all', methods=['POST'])
def restock_all():
    with LOCK:
        for p in DATA['products']: p['stock'] += 50
        save()
    return jsonify(ok=True)

@app.route('/api/return', methods=['POST'])
def api_return():
    d = request.get_json(force=True)
    with LOCK:
        rec = next((r for r in DATA['receipts'] if r['num'] == d.get('num')), None)
        if not rec: return jsonify(error='no receipt'), 404
        items = []; summ = 0.0
        for ri in d.get('items', []):
            orig = next((x for x in rec['items'] if x['name'] == ri['name']), None)
            q = int(ri['qty'])
            if orig and 0 < q <= orig['qty']:
                items.append(dict(name=orig['name'], qty=q, price=orig['price'])); summ += q * orig['price']
        if not items: return jsonify(error='nothing'), 400
        dt_str = datetime.now().strftime('%d.%m.%Y %H:%M')
        ret = dict(num='R%04d' % (len(DATA['returns'])+1), orig=rec['num'], ts=time_ms(),
                   dateTime=dt_str, items=items, sum=round(summ,2), reason=d.get('reason',''))
        for it in items:
            p = next((x for x in DATA['products'] if x['name'] == it['name']), None)
            if p: p['stock'] += it['qty']
        st = DATA['stats']; st['revenue'] -= summ; st['returnsSum'] = st.get('returnsSum',0) + summ
        wp = rec.get('walletPhone')
        if wp and wp in DATA['wallets']:
            DATA['wallets'][wp]['balance'] = round(DATA['wallets'][wp]['balance'] + summ, 2)
        rp = dict(n=ret['num'], mode='view', pt='ВОЗВРАТ', dt=dt_str,
                  t=-int(round(summ*100)), i=[dict(m=i['name'][:14], q=-i['qty']) for i in items])
        ret['code'] = enc_payload(rp)
        DATA['returns'].insert(0, ret); save()
        return jsonify(ok=True, ret=ret)

@app.route('/api/zreport', methods=['POST'])
def api_z():
    with LOCK:
        DATA['stats'] = dict(revenue=0, checks=0, sberPay=0, wallet=0, card=0, cash=0, drawer=0, returnsSum=0)
        DATA['shiftNo'] += 1; DATA['sessions'] = {}; save()
    return jsonify(ok=True, shiftNo=DATA['shiftNo'])

@app.route('/api/settings', methods=['POST'])
def api_settings():
    with LOCK:
        DATA['settings'].update(request.get_json(force=True)); save()
    return jsonify(ok=True)

# ================= ВСТРОЕННЫЙ HTML =================
HTML = r'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Сбер POS / POS-Center OS</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Roboto+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
html{font-size:16px}@media (max-width:640px){html{font-size:14px}}
body{font-family:'Inter',sans-serif;user-select:none;overflow:hidden;background:#e2e8f0}
.font-mono-pos{font-family:'Roboto Mono',monospace}
.desktop-bg{background-color:#f1f5f9;background-image:radial-gradient(at 0% 0%,rgba(34,197,94,.08) 0,transparent 50%),radial-gradient(at 100% 100%,rgba(2,132,199,.08) 0,transparent 50%)}
.pos-window{position:absolute;background:#fff;border:1px solid #cbd5e1;border-radius:.75rem;box-shadow:0 20px 25px -5px rgba(0,0,0,.1);display:flex;flex-direction:column;overflow:hidden}
.pos-window.minimized{opacity:0;transform:scale(.9) translateY(100px);pointer-events:none}
.window-header{background:#f8fafc;border-bottom:1px solid #e2e8f0;cursor:move;touch-action:none}
.pos-table-row-selected{background:#e0f2fe!important;border-left:4px solid #0284c7;font-weight:600}
.thermal-receipt{background:#fff;color:#111827;font-family:'Courier New',monospace;box-shadow:0 10px 30px rgba(0,0,0,.15)}
.price-input{width:5rem;text-align:right;font-weight:700;color:#047857;background:transparent;border:1px solid transparent;border-radius:6px;padding:2px 4px;font-family:'Roboto Mono',monospace;font-size:.69rem;outline:none}
.price-input:focus{border-color:#16a34a;background:#f0fdf4}
.pay-anim{animation:pulse 1s infinite}@keyframes pulse{50%{opacity:.5}}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}
@media (max-width:1023px){.pos-window{left:2vw!important;top:2vh!important;width:96vw!important;height:92vh!important}}
</style>
</head>
<body class="h-screen w-screen desktop-bg relative overflow-hidden">
<div class="absolute inset-0 p-3 sm:p-6 grid grid-cols-3 md:grid-cols-6 gap-3 sm:gap-6 align-content-start z-0">
  <button onclick="windowManager.open('posApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-emerald-500 to-emerald-700 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-cash-register text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold">Касса Сбер POS</span></button>
  <button onclick="windowManager.open('warehouseApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-sky-500 to-sky-700 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-boxes-stacked text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold" id="shortcutWarehouseCount">Склад</span></button>
  <button onclick="windowManager.open('reportsApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-purple-500 to-purple-700 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-chart-pie text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold">Отчеты</span></button>
  <button onclick="windowManager.open('calcApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-amber-500 to-amber-700 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-calculator text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold">Калькулятор</span></button>
  <button onclick="windowManager.open('notesApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-teal-500 to-teal-700 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-note-sticky text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold">Заметки</span></button>
  <button onclick="windowManager.open('settingsApp')" class="flex flex-col items-center p-2 sm:p-3 rounded-xl hover:bg-white/80"><div class="w-12 h-12 sm:w-14 sm:h-14 bg-gradient-to-br from-slate-600 to-slate-800 rounded-2xl flex items-center justify-center text-white shadow-lg"><i class="fa-solid fa-gear text-xl sm:text-2xl"></i></div><span class="mt-2 text-[10px] sm:text-xs font-bold">Настройки</span></button>
</div>
<div id="windowsArea" class="absolute inset-0 pb-12 overflow-hidden pointer-events-none z-10">
<div id="win-posApp" class="pos-window pointer-events-auto" style="width:92vw;height:88vh;top:2vh;left:4vw;z-index:20">
  <div class="window-header h-9 px-2 sm:px-3 flex items-center justify-between" onmousedown="windowManager.dragStart(event,'posApp')">
    <div class="flex items-center gap-2 font-bold text-[10px] sm:text-xs"><div class="w-4 h-4 rounded bg-emerald-600 text-white flex items-center justify-center text-[10px]"><i class="fa-solid fa-cash-register"></i></div><span>Сбер POS Terminal v5.2 · Смена № <span id="shiftLbl">14</span> · <span id="storageBadge" class="text-emerald-700"></span></span></div>
    <div class="flex gap-1"><button onclick="windowManager.minimize('posApp')" class="w-6 h-6 hover:bg-slate-200 rounded text-xs">─</button><button onclick="windowManager.toggleMaximize('posApp')" class="w-6 h-6 hover:bg-slate-200 rounded text-xs">□</button><button onclick="windowManager.close('posApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  </div>
  <div class="flex-1 flex flex-col lg:flex-row overflow-y-auto lg:overflow-hidden bg-slate-100">
    <div class="w-full lg:w-8/12 flex flex-col border-b lg:border-r border-slate-300 bg-white">
      <div class="grid grid-cols-12 bg-slate-200/80 text-slate-700 font-bold text-[9px] sm:text-xs py-2 px-2 border-b"><div class="col-span-1">№</div><div class="col-span-5">Наименование</div><div class="col-span-2 text-right">Цена</div><div class="col-span-2 text-center">Кол-во</div><div class="col-span-2 text-right">Сумма</div></div>
      <div id="posTableBody" class="flex-1 min-h-[160px] max-h-64 lg:max-h-none overflow-y-auto font-mono-pos text-[10px] sm:text-xs divide-y"></div>
      <div class="bg-slate-50 border-t p-2 sm:p-3 flex flex-col lg:flex-row gap-2">
        <div class="flex-1 bg-white rounded-lg border p-2 text-[10px] sm:text-xs">
          <div class="flex justify-between mb-1"><h3 id="posDetailName" class="font-bold truncate flex-1 pr-2">Товар не выбран</h3><span id="posDetailCategory" class="bg-emerald-50 text-emerald-700 border px-1.5 rounded text-[9px] font-mono-pos">—</span></div>
          <div class="grid grid-cols-2 gap-x-3 text-slate-600 font-mono-pos text-[9px] sm:text-[11px]"><div>Код: <b id="posDetailCode">--</b></div><div>Штрихкод: <b id="posDetailBarcode">--</b></div><div>Остаток: <b id="posDetailStock" class="text-emerald-700">--</b></div><div>НДС: <b>20%</b></div></div>
        </div>
        <div class="w-full lg:w-72 bg-slate-900 text-white rounded-lg p-2 sm:p-3 flex flex-col items-end">
          <span class="text-slate-400 text-[9px] font-bold uppercase w-full text-right">ИТОГО К ОПЛАТЕ · Позиций: <span id="posTotalItems" class="text-emerald-400">0</span></span>
          <div id="posTotalDisplay" class="text-2xl sm:text-4xl font-extrabold font-mono-pos">0.00 <span class="text-emerald-400 text-lg sm:text-2xl">₽</span></div>
          <div class="text-[9px] text-slate-400 font-mono-pos">НДС 20%: <span id="posVatDisplay">0.00 ₽</span></div>
        </div>
      </div>
    </div>
    <div class="w-full lg:w-4/12 bg-slate-100 p-2 flex flex-col gap-2">
      <div class="flex gap-1.5">
        <input type="text" id="posSearchInput" placeholder="Штрихкод / Название... (Enter)" class="flex-1 bg-white px-2 py-1.5 rounded-lg border text-[10px] sm:text-xs font-mono-pos" onkeydown="if(event.key==='Enter')scanInput(this.value)">
        <button onclick="openCatalog()" class="px-2 bg-sky-600 text-white font-bold text-[10px] sm:text-xs rounded-lg"><i class="fa-solid fa-boxes-stacked"></i> <span id="posCatalogCount">100</span></button>
      </div>
      <div class="grid grid-cols-3 gap-1 lg:flex-1">
        <button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('1')">1</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('2')">2</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('3')">3</button>
        <button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('4')">4</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('5')">5</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('6')">6</button>
        <button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('7')">7</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('8')">8</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('9')">9</button>
        <button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('0')">0</button><button class="bg-white font-bold text-lg py-2 lg:py-0 rounded-lg border" onclick="numKey('00')">00</button><button class="bg-amber-50 text-amber-800 font-bold py-2 lg:py-0 rounded-lg border border-amber-300" onclick="numKey('C')">Сброс</button>
        <button class="bg-sky-50 text-sky-800 font-bold text-lg py-2 lg:py-0 rounded-lg border border-sky-300" onclick="changeQty(1)">+</button><button class="bg-sky-50 text-sky-800 font-bold text-lg py-2 lg:py-0 rounded-lg border border-sky-300" onclick="changeQty(-1)">-</button><button class="bg-rose-50 text-rose-700 font-bold text-lg py-2 lg:py-0 rounded-lg border border-rose-300" onclick="deleteLine()"><i class="fa-solid fa-trash-can"></i></button>
      </div>
      <div class="grid grid-cols-2 gap-1">
        <button class="py-2 bg-slate-200 font-bold text-[10px] sm:text-xs rounded-lg" onclick="addRandom()"><i class="fa-solid fa-bolt text-amber-600 mr-1"></i>Случайный</button>
        <button class="py-2 bg-rose-100 text-rose-800 font-bold text-[10px] sm:text-xs rounded-lg border border-rose-300" onclick="clearCheck()"><i class="fa-solid fa-xmark mr-1"></i>Отмена чека</button>
      </div>
      <button class="h-14 sm:h-16 bg-gradient-to-r from-emerald-600 to-emerald-700 text-white font-extrabold text-base sm:text-xl rounded-xl shadow-lg border border-emerald-400 flex items-center justify-center gap-2 uppercase" onclick="openPayment()"><i class="fa-solid fa-credit-card text-xl"></i><span>Оплата (F12)</span></button>
    </div>
  </div>
</div>
<div id="win-warehouseApp" class="pos-window pointer-events-auto minimized" style="width:84vw;height:82vh;top:6vh;left:8vw;z-index:21">
  <div class="window-header h-9 px-2 flex items-center justify-between" onmousedown="windowManager.dragStart(event,'warehouseApp')">
    <div class="flex items-center gap-2 font-bold text-[10px] sm:text-xs"><div class="w-4 h-4 rounded bg-sky-600 text-white flex items-center justify-center text-[10px]"><i class="fa-solid fa-boxes-stacked"></i></div><span>Склад и Учет</span></div>
    <div class="flex gap-1"><button onclick="windowManager.minimize('warehouseApp')" class="w-6 h-6 hover:bg-slate-200 rounded text-xs">─</button><button onclick="windowManager.close('warehouseApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  </div>
  <div class="flex-1 flex flex-col bg-slate-50 overflow-hidden">
    <div class="p-2 bg-white border-b flex flex-wrap gap-2 items-center">
      <input type="text" id="warehouseSearch" placeholder="Поиск..." class="flex-1 min-w-[120px] bg-slate-50 border rounded-lg px-3 py-1.5 text-[10px] sm:text-xs font-mono-pos" oninput="renderWarehouse()">
      <select id="warehouseCategoryFilter" class="bg-slate-50 border rounded-lg px-2 py-1.5 text-[10px] sm:text-xs" onchange="renderWarehouse()"><option value="Все">Все категории</option><option>Бакалея</option><option>Молочные продукты</option><option>Напитки</option><option>Выпечка и Хлеб</option><option>Овощи и Фрукты</option><option>Заморозка</option><option>Мясо и Колбасы</option><option>Бытовая химия</option><option>Сладости и Снеки</option><option>Хозтовары</option></select>
      <button onclick="openAddModal()" class="px-2 py-1.5 bg-emerald-600 text-white font-bold text-[10px] sm:text-xs rounded-lg"><i class="fa-solid fa-plus mr-1"></i>Добавить</button>
      <button onclick="restockAll()" class="px-2 py-1.5 bg-sky-600 text-white font-bold text-[10px] sm:text-xs rounded-lg">+50 все</button>
    </div>
    <div class="flex-1 overflow-auto p-2">
      <table class="w-full min-w-[680px] text-left text-[10px] sm:text-xs bg-white border"><thead class="bg-slate-100 font-bold border-b"><tr><th class="p-2">Код</th><th class="p-2">Штрихкод</th><th class="p-2">Наименование</th><th class="p-2">Категория</th><th class="p-2 text-right">Цена ₽</th><th class="p-2 text-center">Остаток</th><th class="p-2 text-center">Статус</th><th class="p-2 text-center">Действие</th></tr></thead><tbody id="warehouseTableBody" class="divide-y font-mono-pos"></tbody></table>
    </div>
    <div class="p-2 bg-white border-t text-[10px] sm:text-xs flex justify-between font-mono-pos"><span>Карточек: <b id="warehouseCount">100</b></span><span>Стоимость склада: <b id="warehouseTotalValue" class="text-emerald-700">0 ₽</b></span></div>
  </div>
</div>
<div id="win-reportsApp" class="pos-window pointer-events-auto minimized" style="width:86vw;height:84vh;top:4vh;left:7vw;z-index:22">
  <div class="window-header h-9 px-2 flex items-center justify-between" onmousedown="windowManager.dragStart(event,'reportsApp')">
    <div class="flex items-center gap-2 font-bold text-[10px] sm:text-xs"><div class="w-4 h-4 rounded bg-purple-600 text-white flex items-center justify-center text-[10px]"><i class="fa-solid fa-chart-pie"></i></div><span>Финансовые Отчеты и Z-Отчет</span></div>
    <div class="flex gap-1"><button onclick="windowManager.minimize('reportsApp')" class="w-6 h-6 hover:bg-slate-200 rounded text-xs">─</button><button onclick="windowManager.close('reportsApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  </div>
  <div class="flex-1 bg-slate-50 p-3 overflow-y-auto space-y-3">
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-2">
      <div class="bg-white p-3 rounded-xl border"><span class="text-slate-500 text-[9px] font-bold uppercase">Выручка</span><div id="repTotalRevenue" class="text-lg font-extrabold text-emerald-600 font-mono-pos">0 ₽</div></div>
      <div class="bg-white p-3 rounded-xl border"><span class="text-slate-500 text-[9px] font-bold uppercase">Чеков</span><div id="repChecksCount" class="text-lg font-extrabold font-mono-pos">0</div></div>
      <div class="bg-white p-3 rounded-xl border"><span class="text-slate-500 text-[9px] font-bold uppercase">Средний чек</span><div id="repAvgCheck" class="text-lg font-extrabold text-sky-600 font-mono-pos">0 ₽</div></div>
      <div class="bg-white p-3 rounded-xl border"><span class="text-slate-500 text-[9px] font-bold uppercase">В ящике</span><div id="repCashDrawer" class="text-lg font-extrabold text-amber-600 font-mono-pos">0 ₽</div></div>
    </div>
    <div class="bg-white p-3 rounded-xl border space-y-2">
      <h3 class="font-bold text-xs border-b pb-2">Разбивка по способам оплаты</h3>
      <div class="font-mono-pos text-[10px] space-y-2">
        <div><div class="flex justify-between mb-1"><span><i class="fa-solid fa-qrcode text-emerald-600 mr-1"></i>СберPay (QR с телефона):</span><b id="repSberPayVal">0</b></div><div class="w-full bg-slate-100 h-2 rounded-full"><div id="repSberPayBar" class="bg-emerald-500 h-full w-0"></div></div></div>
        <div><div class="flex justify-between mb-1"><span><i class="fa-solid fa-mobile-screen text-pink-600 mr-1"></i>Карта телефона (по номеру):</span><b id="repWalletVal">0</b></div><div class="w-full bg-slate-100 h-2 rounded-full"><div id="repWalletBar" class="bg-pink-500 h-full w-0"></div></div></div>
      </div>
    </div>
    <div class="bg-white p-3 rounded-xl border"><h3 class="font-bold text-xs border-b pb-2 mb-2">📊 Дашборд смены</h3><canvas id="chartHours" class="w-full block mb-2" height="140"></canvas><canvas id="chartTop" class="w-full block" height="140"></canvas></div>
    <div class="bg-white p-3 rounded-xl border"><h3 class="font-bold text-xs border-b pb-2 mb-2">История чеков</h3><div id="receiptsHistory" class="space-y-1 max-h-44 overflow-y-auto text-[10px]"></div></div>
    <div class="bg-white p-3 rounded-xl border">
      <div class="flex justify-between items-center border-b pb-2 mb-2"><h3 class="font-bold text-xs">🔄 Возвраты <span id="repReturnsVal" class="text-rose-600 font-mono-pos"></span></h3><button onclick="openReturnModal()" class="px-3 py-1.5 bg-rose-600 text-white font-bold text-[10px] rounded-lg"><i class="fa-solid fa-rotate-left mr-1"></i>Оформить возврат</button></div>
      <div id="returnsList" class="space-y-1 max-h-32 overflow-y-auto text-[10px]"></div>
    </div>
    <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 flex justify-between items-center"><div><h4 class="font-bold text-amber-900 text-[10px]">Закрытие смены (Z-Отчет)</h4><p class="text-[9px] text-amber-700">Фискальный отчет в ОФД</p></div><button onclick="zReport()" class="px-4 py-2 bg-amber-600 text-white font-bold text-[10px] rounded-lg uppercase">Снять Z-Отчет</button></div>
  </div>
</div>
<div id="win-calcApp" class="pos-window pointer-events-auto minimized" style="width:300px;height:400px;top:15vh;left:35vw;z-index:23">
  <div class="window-header h-9 px-3 flex items-center justify-between"><span class="font-bold text-xs">Калькулятор POS</span><button onclick="windowManager.close('calcApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  <div class="flex-1 bg-slate-100 p-3 flex flex-col gap-2"><div id="calcDisplay" class="bg-white border rounded-lg p-3 text-right font-mono-pos text-2xl font-bold h-14 flex items-center justify-end">0</div>
  <div class="grid grid-cols-4 gap-2 flex-1 font-bold"><button onclick="calcBtn('C')" class="bg-rose-100 rounded-lg border">C</button><button onclick="calcBtn('(')" class="bg-slate-200 rounded-lg border">(</button><button onclick="calcBtn(')')" class="bg-slate-200 rounded-lg border">)</button><button onclick="calcBtn('/')" class="bg-sky-100 rounded-lg border">÷</button><button onclick="calcBtn('7')" class="bg-white rounded-lg border">7</button><button onclick="calcBtn('8')" class="bg-white rounded-lg border">8</button><button onclick="calcBtn('9')" class="bg-white rounded-lg border">9</button><button onclick="calcBtn('*')" class="bg-sky-100 rounded-lg border">×</button><button onclick="calcBtn('4')" class="bg-white rounded-lg border">4</button><button onclick="calcBtn('5')" class="bg-white rounded-lg border">5</button><button onclick="calcBtn('6')" class="bg-white rounded-lg border">6</button><button onclick="calcBtn('-')" class="bg-sky-100 rounded-lg border">-</button><button onclick="calcBtn('1')" class="bg-white rounded-lg border">1</button><button onclick="calcBtn('2')" class="bg-white rounded-lg border">2</button><button onclick="calcBtn('3')" class="bg-white rounded-lg border">3</button><button onclick="calcBtn('+')" class="bg-sky-100 rounded-lg border">+</button><button onclick="calcBtn('0')" class="col-span-2 bg-white rounded-lg border">0</button><button onclick="calcBtn('.')" class="bg-white rounded-lg border">.</button><button onclick="calcBtn('=')" class="bg-emerald-600 text-white rounded-lg border">=</button></div></div>
</div>
<div id="win-notesApp" class="pos-window pointer-events-auto minimized" style="width:92vw;max-width:450px;height:380px;top:20vh;left:4vw;z-index:24">
  <div class="window-header h-9 px-3 flex items-center justify-between"><span class="font-bold text-xs">Заметки Смены</span><button onclick="windowManager.close('notesApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  <div class="flex-1 bg-amber-50/50 p-3 flex flex-col gap-2"><textarea id="notesArea" class="flex-1 w-full p-3 bg-white border rounded-lg text-xs font-mono-pos resize-none"></textarea><div class="flex justify-between items-center"><span class="text-[10px] text-slate-500 font-mono-pos">Локально (браузер)</span><button onclick="saveNotes()" class="px-3 py-1 bg-teal-600 text-white font-bold text-xs rounded">Сохранить</button></div></div>
</div>
<div id="win-settingsApp" class="pos-window pointer-events-auto minimized" style="width:92vw;max-width:500px;height:460px;top:12vh;left:4vw;z-index:25">
  <div class="window-header h-9 px-3 flex items-center justify-between"><span class="font-bold text-xs">Настройки POS-ОС</span><button onclick="windowManager.close('settingsApp')" class="w-6 h-6 hover:bg-rose-500 hover:text-white rounded text-xs">✕</button></div>
  <div class="flex-1 bg-slate-50 p-4 space-y-3 text-xs overflow-y-auto">
    <div class="bg-emerald-50 border border-emerald-200 rounded-lg p-2.5"><b class="text-emerald-800">📡 Адрес сервера для телефона:</b><div id="srvUrl" class="font-mono-pos text-emerald-700 break-all"></div><div class="text-[10px] text-emerald-700 mt-1">Этот адрес встроен в каждый QR оплаты</div></div>
    <div class="bg-sky-50 border border-sky-200 rounded-lg p-2.5 space-y-2">
      <b class="text-sky-800 text-[11px]">💾 Резервная копия данных (хостинг)</b>
      <div class="flex gap-2">
        <a href="/api/backup" download="sberpos_data.json" class="flex-1 text-center py-2 bg-sky-600 text-white font-bold rounded-lg text-[11px]">Скачать копию</a>
        <label class="flex-1 text-center py-2 bg-sky-100 text-sky-800 font-bold rounded-lg text-[11px] cursor-pointer">Восстановить<input type="file" id="restoreFile" accept=".json,application/json" class="hidden" onchange="restoreBackup(this)"></label>
      </div>
      <div id="storageInfo" class="text-[10px] text-sky-700 font-mono-pos"></div>
      <div class="text-[9px] text-sky-700">На хостинге файловая система временная: после редеплоя данные сбрасываются. Скачивайте копию и восстанавливайте её после каждого деплоя.</div>
    </div>
    <div><label class="block font-bold mb-1">Торговая точка:</label><input id="cfgStoreName" class="w-full bg-white border rounded-lg p-2 font-mono-pos"></div>
    <div><label class="block font-bold mb-1">ИНН:</label><input id="cfgInn" class="w-full bg-white border rounded-lg p-2 font-mono-pos"></div>
    <div><label class="block font-bold mb-1">Кассир:</label><input id="cfgCashier" class="w-full bg-white border rounded-lg p-2 font-mono-pos"></div>
    <button onclick="saveSettings()" class="w-full py-2 bg-emerald-600 text-white font-bold rounded-lg">Сохранить настройки</button>
  </div>
</div>
</div>
<footer class="absolute bottom-0 inset-x-0 h-11 bg-white/95 backdrop-blur border-t px-2 flex items-center justify-between z-40 shadow-md">
  <div class="flex items-center gap-2"><div class="h-8 px-3 bg-gradient-to-r from-emerald-600 to-emerald-700 text-white font-bold text-xs rounded-lg flex items-center gap-2"><i class="fa-solid fa-leaf"></i><span class="hidden sm:inline">Сбер POS</span></div><div id="taskbarItems" class="flex items-center gap-1.5 overflow-x-auto"></div></div>
  <div class="flex items-center gap-3 text-[10px] sm:text-xs font-mono-pos text-slate-600"><span class="text-emerald-700 font-semibold"><i class="fa-solid fa-database mr-1"></i>Flask: ОК</span><span class="hidden sm:inline text-emerald-700">ОФД: ОК</span><div class="text-right leading-tight"><div id="taskbarTime" class="font-bold text-slate-900">--:--:--</div><div id="taskbarDate" class="text-[9px] text-slate-500"></div></div></div>
</footer>
<div id="paymentModal" class="hidden fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-2">
  <div class="bg-white rounded-2xl w-full max-w-xl max-h-[94vh] overflow-y-auto shadow-2xl">
    <div class="p-3 bg-emerald-700 text-white flex justify-between items-center"><div><h3 class="font-bold text-sm">Оплата заказа</h3><p class="text-[10px] text-emerald-100">QR — списание с телефона · по номеру — списание с баланса карты</p></div><button onclick="closePayment()" class="text-2xl font-bold">✕</button></div>
    <div class="p-3 space-y-3 bg-slate-50">
      <div class="bg-white p-3 rounded-xl border flex justify-between items-center"><span class="text-[10px] font-bold uppercase text-slate-600">Итого к оплате:</span><span id="payModalTotal" class="text-2xl font-extrabold font-mono-pos text-emerald-700">0.00 ₽</span></div>
      <div class="bg-white p-3 rounded-xl border space-y-2">
        <div class="flex justify-between items-center"><span class="text-[10px] font-bold uppercase text-slate-600"><i class="fa-solid fa-heart text-pink-500 mr-1"></i>СберСпасибо и скидки</span><button onclick="toggleClientPanel()" class="px-2 py-1 bg-pink-100 text-pink-700 font-bold text-[10px] rounded-lg">💚 Клиент</button></div>
        <div id="clientPanel" class="hidden space-y-2 bg-pink-50/50 border border-pink-200 rounded-lg p-2">
          <div class="flex gap-2"><input id="clientPhone" placeholder="79991234567" class="flex-1 bg-white border rounded-lg px-2 py-1.5 text-[11px] font-mono-pos"><button onclick="findClient()" class="px-3 bg-pink-600 text-white font-bold text-[10px] rounded-lg">Найти</button></div>
          <div id="clientInfo" class="text-[10px] font-mono-pos"></div>
          <div id="bonusRow" class="hidden items-center gap-2"><span class="text-[10px] font-bold text-purple-700">Списать бонусов:</span><input id="bonusWriteInput" type="number" min="0" value="0" oninput="onBonusInput(this.value)" class="w-20 bg-white border rounded-lg px-2 py-1 text-[11px] font-mono-pos"><span id="bonusHint" class="text-[9px] text-slate-500"></span></div>
        </div>
        <div class="flex gap-2 items-center"><input id="promoInput" placeholder="Промокод (VESNA2026)" class="flex-1 bg-white border rounded-lg px-2 py-1.5 text-[11px] font-mono-pos uppercase"><button onclick="applyPromo()" class="px-3 bg-emerald-600 text-white font-bold text-[10px] rounded-lg">Применить</button><span id="promoInfo" class="text-[10px] font-bold"></span></div>
        <div id="discountBreakdown" class="text-[10px] font-mono-pos text-slate-600 space-y-0.5"></div>
      </div>
      <div class="bg-white p-3 rounded-xl border space-y-2">
        <div class="flex justify-between items-center"><span class="text-[10px] font-bold uppercase text-slate-600"><i class="fa-solid fa-mobile-screen text-emerald-600 mr-1"></i>Оплата по номеру телефона</span><span class="text-[9px] text-slate-400">баланс карты + баллы</span></div>
        <div class="flex gap-2"><input id="walletPhone" placeholder="79991234567" class="flex-1 bg-white border rounded-lg px-2 py-1.5 text-[11px] font-mono-pos"><button onclick="loadWallet()" class="px-3 bg-emerald-600 text-white font-bold text-[10px] rounded-lg">Показать</button></div>
        <div id="walletInfo" class="text-[10px] font-mono-pos text-slate-600"></div>
        <button id="payWalletBtn" onclick="payWallet()" disabled class="w-full py-2.5 bg-emerald-600 text-white font-bold text-[11px] rounded-lg disabled:opacity-40">Списать с баланса телефона</button>
      </div>
      <div class="bg-white rounded-xl border flex flex-col items-center p-3 space-y-2">
        <div class="w-56 h-56 sm:w-72 sm:h-72 bg-white p-3 rounded-lg border relative flex items-center justify-center"><img id="sberQrImg" src="" class="w-full h-full" style="image-rendering:pixelated"><div id="qrSpinner" class="absolute w-10 h-10 border-4 border-emerald-200 border-t-emerald-600 rounded-full animate-spin"></div></div>
        <div id="payCodeText" class="font-mono-pos text-[8px] text-slate-500 bg-slate-100 px-2 py-1 rounded select-all break-all max-w-full max-h-10 overflow-hidden"></div>
        <div id="sberStatus" class="text-[10px] font-bold text-amber-700 pay-anim">⏳ Ожидание оплаты с телефона...</div>
        <p class="text-[9px] text-slate-500 text-center">QR — оплата с телефона покупателя. Либо спишите с баланса по номеру выше.</p>
      </div>
    </div>
  </div>
</div>
<div id="receiptModal" class="hidden fixed inset-0 z-50 bg-slate-900/80 flex items-center justify-center p-2">
  <div class="w-full max-w-[92vw] sm:max-w-sm flex flex-col items-center">
    <div class="thermal-receipt w-full p-4 rounded-t-xl text-[10px] space-y-2 max-h-[75vh] overflow-y-auto">
      <div class="text-center"><h2 class="font-bold text-xs uppercase" id="recStore"></h2><p class="text-[9px]">Кассовый чек № <span id="recNum"></span></p><p class="text-[9px]" id="recInn"></p><p class="text-[9px]" id="recDateTime"></p><div class="border-b border-dashed border-gray-400 my-2"></div></div>
      <div id="recItemsList" class="space-y-1 font-mono"></div>
      <div class="border-b border-dashed border-gray-400 my-2"></div>
      <div class="space-y-1 font-bold"><div class="flex justify-between text-xs"><span>ИТОГ:</span><span id="recTotal"></span></div><div class="flex justify-between text-[9px] font-normal"><span>НДС 20%:</span><span id="recVat"></span></div><div class="flex justify-between text-[9px] font-normal"><span>Оплата:</span><span id="recPayType"></span></div></div>
      <div class="border-b border-dashed border-gray-400 my-2"></div>
      <div class="text-center space-y-1 text-[8px]"><p id="recFiscal"></p><div class="flex justify-center pt-1"><img id="recQrImg" class="w-36 h-36" style="image-rendering:pixelated"></div><p class="text-[8px]">QR чека: сканируется приложением в режиме просмотра</p><p class="font-bold text-gray-900 text-[10px]">СПАСИБО ЗА ПОКУПКУ!</p></div>
    </div>
    <div class="w-full bg-white p-3 rounded-b-xl flex gap-2"><button onclick="window.print()" class="flex-1 py-2 bg-sky-600 text-white font-bold rounded text-xs">Печать</button><button onclick="hide('receiptModal')" class="flex-1 py-2 bg-slate-800 text-white font-bold rounded text-xs">Закрыть</button></div>
  </div>
</div>
<div id="catalogModal" class="hidden fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-2">
  <div class="bg-white rounded-xl w-full max-w-3xl max-h-[85vh] flex flex-col overflow-hidden">
    <div class="p-3 bg-slate-100 border-b flex justify-between items-center"><h3 class="font-bold text-sm" id="catalogModalTitle">Каталог</h3><button onclick="hide('catalogModal')" class="text-xl font-bold text-slate-400">✕</button></div>
    <div class="p-3 bg-slate-50 border-b"><input id="catalogModalSearch" placeholder="Поиск..." class="w-full bg-white border rounded-lg px-3 py-1.5 text-xs" oninput="renderCatalog()"></div>
    <div id="catalogModalGrid" class="p-3 grid grid-cols-2 sm:grid-cols-3 gap-2 overflow-y-auto flex-1"></div>
  </div>
</div>
<div id="addProductModal" class="hidden fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-2">
  <div class="bg-white rounded-2xl w-full max-w-md max-h-[94vh] overflow-y-auto">
    <div class="p-3 bg-sky-600 text-white flex justify-between items-center"><h3 class="font-bold text-sm">Добавить товар</h3><button onclick="hide('addProductModal')" class="text-2xl font-bold">✕</button></div>
    <div class="p-4 space-y-3 text-xs">
      <input id="apName" placeholder="Наименование *" class="w-full border rounded-lg p-2 font-mono-pos">
      <div class="grid grid-cols-2 gap-3"><input id="apCode" placeholder="Код" class="border rounded-lg p-2 font-mono-pos"><input id="apBarcode" placeholder="Штрихкод" class="border rounded-lg p-2 font-mono-pos"></div>
      <div class="grid grid-cols-2 gap-3"><select id="apCategory" class="border rounded-lg p-2"><option>Бакалея</option><option>Молочные продукты</option><option>Напитки</option><option>Выпечка и Хлеб</option><option>Овощи и Фрукты</option><option>Заморозка</option><option>Мясо и Колбасы</option><option>Бытовая химия</option><option>Сладости и Снеки</option><option>Хозтовары</option></select><select id="apUnit" class="border rounded-lg p-2"><option>шт</option><option>кг</option><option>л</option></select></div>
      <div class="grid grid-cols-2 gap-3"><input id="apPrice" type="number" step="0.01" placeholder="Цена ₽ *" class="border rounded-lg p-2 font-mono-pos"><input id="apStock" type="number" value="0" placeholder="Остаток" class="border rounded-lg p-2 font-mono-pos"></div>
      <div class="flex gap-2"><button onclick="hide('addProductModal')" class="flex-1 py-2.5 bg-slate-200 font-bold rounded-lg">Отмена</button><button onclick="addProduct()" class="flex-1 py-2.5 bg-emerald-600 text-white font-bold rounded-lg">Добавить</button></div>
    </div>
  </div>
</div>
<div id="returnModal" class="hidden fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-2">
  <div class="bg-white rounded-2xl w-full max-w-md max-h-[94vh] overflow-y-auto">
    <div class="p-3 bg-rose-600 text-white flex justify-between items-center"><h3 class="font-bold text-sm">Оформление возврата</h3><button onclick="hide('returnModal')" class="text-2xl font-bold">✕</button></div>
    <div class="p-4 space-y-3 text-xs">
      <select id="retReceipt" onchange="onRetChange()" class="w-full border rounded-lg p-2 font-mono-pos"></select>
      <div id="retItems" class="space-y-1.5 max-h-52 overflow-y-auto"></div>
      <select id="retReason" class="w-full border rounded-lg p-2"><option>Возврат покупателем (качество)</option><option>Не подошел товар</option><option>Ошибка кассира</option><option>Брак / просрок</option></select>
      <div class="flex justify-between bg-rose-50 border border-rose-200 rounded-lg p-2.5"><span class="font-bold text-rose-700">Сумма возврата:</span><span id="retSum" class="font-extrabold font-mono-pos text-lg text-rose-700">0.00 ₽</span></div>
      <div class="flex gap-2"><button onclick="hide('returnModal')" class="flex-1 py-2.5 bg-slate-200 font-bold rounded-lg">Отмена</button><button onclick="submitReturn()" class="flex-1 py-2.5 bg-rose-600 text-white font-bold rounded-lg">Оформить</button></div>
    </div>
  </div>
</div>
<script>
let state=null,cart=[],sel=-1,buffer='';
let curSession=null,pollTimer=null,curClient=null,curPromo=null,curWrite=0,retCurrent=null,curWallet=null,calcExpr='';
const $=id=>document.getElementById(id);
const fmt=n=>(+n||0).toLocaleString('ru-RU',{minimumFractionDigits:2,maximumFractionDigits:2});
const qrUrl=(hex,size)=>'https://api.qrserver.com/v1/create-qr-code/?size='+size+'x'+size+'&ecc=L&qzone=4&data='+encodeURIComponent('sberpay://pay?code='+hex);
async function api(p,o){const r=await fetch(p,Object.assign({headers:{'Content-Type':'application/json'}},o));return r.json();}
async function loadState(){state=await api('/api/state');renderAll();}
function renderAll(){updateCounts();renderKassa();renderWarehouse();renderReports();$('shiftLbl').textContent=state.shiftNo;$('srvUrl').textContent=state.srv;$('cfgStoreName').value=state.settings.storeName;$('cfgInn').value=state.settings.inn;$('cfgCashier').value=state.settings.cashier;
$('storageBadge').textContent=(state.storage==='file'?'файл':'ОЗУ');refreshStorageInfo();}
function prod(id){return state.products.find(p=>p.id===id);}
function updateCounts(){const n=state.products.length;$('warehouseCount').textContent=n;$('shortcutWarehouseCount').textContent='Склад ('+n+')';$('posCatalogCount').textContent=n;$('catalogModalTitle').textContent='Каталог '+n+' товаров';}
function hide(id){$(id).classList.add('hidden');}
function show(id){$(id).classList.remove('hidden');}
function toast(msg){const t=document.createElement('div');t.className='fixed bottom-14 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-[10px] sm:text-xs font-mono-pos px-4 py-2.5 rounded-xl shadow-2xl z-[70] max-w-[90vw]';t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),2800);}
async function refreshStorageInfo(){try{const h=await api('/api/health');
$('storageInfo').textContent='Режим: '+(h.mode==='file'?('файл '+h.data_file):'ОЗУ (данные до рестарта)')+' · чеков: '+h.receipts;}catch(e){}}
async function restoreBackup(inp){const f=inp.files&&inp.files[0];if(!f)return;
const txt=await f.text();
try{const obj=JSON.parse(txt);
const res=await fetch('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj)});
const j=await res.json();
if(j.ok){toast('✓ Данные восстановлены'+(j.saved?' и записаны в файл':' (режим ОЗУ)'));await loadState();}
else toast('Ошибка восстановления: файл не похож на резервную копию');}
catch(e){toast('Файл не читается: '+e);}
inp.value='';}
function renderKassa(){const tb=$('posTableBody');tb.innerHTML='';let total=0;
if(!cart.length)tb.innerHTML='<div class="text-center text-slate-400 py-10">Чек пуст</div>';
cart.forEach((l,i)=>{const p=prod(l.id);const s=p.price*l.qty;total+=s;const r=document.createElement('div');r.className='grid grid-cols-12 py-2 px-2 items-center cursor-pointer '+(i===sel?'pos-table-row-selected':'hover:bg-slate-50');r.onclick=()=>{sel=i;renderKassa();};r.innerHTML='<div class="col-span-1 text-slate-500 font-bold">'+(i+1)+'</div><div class="col-span-5 truncate">'+p.name+'</div><div class="col-span-2 text-right">'+p.price.toFixed(2)+'</div><div class="col-span-2 text-center font-bold">'+l.qty+'</div><div class="col-span-2 text-right font-bold">'+s.toFixed(2)+'</div>';tb.appendChild(r);});
$('posTotalDisplay').innerHTML=fmt(total)+' <span class="text-emerald-400 text-lg sm:text-2xl">₽</span>';
$('posVatDisplay').textContent=fmt(total*20/120)+' ₽';$('posTotalItems').textContent=cart.length;
const s=sel>=0?prod(cart[sel].id):null;
$('posDetailName').textContent=s?s.name:'Товар не выбран';$('posDetailCategory').textContent=s?s.category:'—';$('posDetailCode').textContent=s?s.code:'--';$('posDetailBarcode').textContent=s?s.barcode:'--';$('posDetailStock').textContent=s?s.stock+' '+s.unit:'--';}
function scanInput(v){if(!v)return;const f=state.products.find(p=>p.barcode===v.trim()||p.code===v.trim()||p.name.toLowerCase().includes(v.toLowerCase()));if(f){addItem(f.id);}else toast('Не найдено: '+v);}
function addItem(id){const p=prod(id);const e=cart.find(l=>l.id===id);const inCart=e?e.qty:0;
if(p.stock<=inCart){toast('Лимит остатка');return;}
if(e)e.qty++;else{cart.push({id:id,qty:1});sel=cart.length-1;}renderKassa();}
function numKey(k){if(k==='C'){buffer='';if(sel>=0&&cart[sel])cart[sel].qty=1;renderKassa();}else{buffer=(buffer+k).slice(-12);const f=state.products.find(p=>p.code===buffer||p.barcode===buffer);if(f){addItem(f.id);buffer='';}renderKassa();}}
function changeQty(d){if(sel<0||!cart[sel])return;const l=cart[sel];const p=prod(l.id);
if(d>0&&l.qty>=p.stock){toast('Лимит остатка');return;}l.qty+=d;if(l.qty<1){cart.splice(sel,1);sel=Math.max(0,cart.length-1);}renderKassa();}
function deleteLine(){if(sel>=0&&cart.length){cart.splice(sel,1);sel=Math.min(sel,cart.length-1);renderKassa();}}
function addRandom(){const a=state.products.filter(p=>p.stock>0);if(a.length)addItem(a[Math.floor(Math.random()*a.length)].id);}
function clearCheck(){cart=[];sel=-1;renderKassa();}
async function openPayment(){if(!cart.length){toast('Чек пуст!');return;}
curClient=null;curPromo=null;curWrite=0;curWallet=null;
$('clientPanel').classList.add('hidden');$('clientInfo').innerHTML='';$('bonusRow').classList.add('hidden');
$('promoInput').value='';$('promoInfo').textContent='';
$('walletPhone').value='';$('walletInfo').innerHTML='';$('payWalletBtn').disabled=true;
show('paymentModal');await startSession();startPoll();}
function closePayment(){hide('paymentModal');stopPoll();curSession=null;}
async function startSession(){const res=await api('/api/session/start',{method:'POST',body:JSON.stringify({items:cart.map(l=>({id:l.id,qty:l.qty})),clientPhone:curClient?curClient.phone:null,promo:curPromo,write:curWrite})});
curSession=res;renderBreakdown(res.pricing);
$('payModalTotal').textContent=fmt(res.pricing.payable)+' ₽';
$('qrSpinner').style.display='block';const img=$('sberQrImg');img.onload=()=>$('qrSpinner').style.display='none';img.src=qrUrl(res.code,400);$('payCodeText').textContent=res.code;
if(($('walletPhone').value||'').replace(/\D/g,'').length>=10)loadWallet();}
function renderBreakdown(p){let h='<div class="flex justify-between"><span>Сумма без скид:</span><span>'+fmt(p.subtotal)+' ₽</span></div>';
if(p.happy>0)h+='<div class="flex justify-between text-pink-600"><span>🕗 Счастливые часы −20%:</span><span>−'+fmt(p.happy)+' ₽</span></div>';
if(p.promoDisc>0)h+='<div class="flex justify-between text-pink-600"><span>🎟 Промокод '+curPromo+':</span><span>−'+fmt(p.promoDisc)+' ₽</span></div>';
if(p.sumDisc>0)h+='<div class="flex justify-between text-pink-600"><span>💰 Скидка от суммы −5%:</span><span>−'+fmt(p.sumDisc)+' ₽</span></div>';
if(p.write>0)h+='<div class="flex justify-between text-purple-600"><span>💚 Бонусами:</span><span>−'+fmt(p.write)+' ₽</span></div>';
if(curClient)h+='<div class="flex justify-between text-emerald-600"><span>✨ Начислится ('+p.level+', '+p.pct+'%):</span><span>+'+p.accrual+' б</span></div>';
$('discountBreakdown').innerHTML=h;
$('bonusWriteInput').max=p.maxWrite;$('bonusHint').textContent='макс '+p.maxWrite;}
function startPoll(){stopPoll();pollTimer=setInterval(async()=>{if(!curSession)return;
const st=await api('/api/session/status?sid='+curSession.sid);
if(st.status==='done'){stopPoll();closePayment();showReceipt(st.receipt);loadState();toast('✓ Телефон оплатил — чек пробит!');}},1200);}
function stopPoll(){if(pollTimer){clearInterval(pollTimer);pollTimer=null;}}
function toggleClientPanel(){$('clientPanel').classList.toggle('hidden');}
async function findClient(){const digits=($('clientPhone').value||'').replace(/\D/g,'');
const r=await api('/api/client?phone='+digits);
if(!r.found){curClient=null;$('clientInfo').innerHTML='<span class="text-rose-600 font-bold">Клиент не найден</span>';$('bonusRow').classList.add('hidden');}
else{curClient=r.client;if(r.created)toast('💚 Клиент создан: +100 приветственных бонусов');
$('clientInfo').innerHTML='<b>'+r.client.name+'</b> · '+r.level+' · баллы: <b class="text-purple-700">'+r.client.bonus+' б</b> · баланс карты: <b class="text-emerald-700">'+fmt(r.wallet)+' ₽</b>';
$('bonusRow').classList.remove('hidden');$('bonusRow').style.display='flex';$('bonusWriteInput').value=0;curWrite=0;
$('walletPhone').value=digits;loadWallet();}
await startSession();}
function onBonusInput(v){curWrite=parseInt(v)||0;startSession();}
async function applyPromo(){const c=($('promoInput').value||'').trim().toUpperCase();
curPromo=['VESNA2026','SBER10','SALE5'].includes(c)?c:null;
$('promoInfo').textContent=curPromo?'✓':'✗';$('promoInfo').className='text-[10px] font-bold '+(curPromo?'text-emerald-600':'text-rose-600');
await startSession();}
async function loadWallet(){const digits=($('walletPhone').value||'').replace(/\D/g,'');
if(digits.length<10){$('walletInfo').innerHTML='<span class="text-rose-600 font-bold">Введите номер (10-11 цифр)</span>';$('payWalletBtn').disabled=true;return;}
const r=await api('/api/wallet?phone='+digits);
if(!r.found){$('walletInfo').innerHTML='<span class="text-rose-600">Не найдено</span>';$('payWalletBtn').disabled=true;curWallet=null;return;}
curWallet=r;
$('walletInfo').innerHTML='<b>'+r.name+'</b> · баланс: <b class="text-emerald-700">'+fmt(r.balance)+' ₽</b> · баллы: <b class="text-purple-700">'+r.bonus+' б</b> ('+r.level+')<br>+10 000 ₽/день · последнее пополнение: '+r.lastTopup;
updateWalletBtn();}
function updateWalletBtn(){const pay=curSession?curSession.pricing.payable:0;
const ok=curWallet&&curWallet.balance>=pay-1e-9;
$('payWalletBtn').disabled=!ok;
$('payWalletBtn').textContent=ok?('Списать '+fmt(pay)+' ₽ с баланса телефона'):'Недостаточно средств на балансе телефона';}
async function payWallet(){if(!curSession||!curWallet)return;
const digits=($('walletPhone').value||'').replace(/\D/g,'');
const res=await api('/api/wallet/pay',{method:'POST',body:JSON.stringify({sid:curSession.sid,phone:digits})});
if(res.ok){stopPoll();closePayment();showReceipt(res.receipt);loadState();toast('✓ Оплата по номеру: списано '+fmt(res.receipt.total)+' ₽, остаток '+fmt(res.balance)+' ₽');}
else if(res.error==='insufficient'){toast('Недостаточно средств на балансе телефона: '+fmt(res.balance)+' ₽');loadWallet();}
else toast('Ошибка оплаты по номеру');}
function showReceipt(r){$('recStore').textContent=state.settings.storeName;$('recNum').textContent=r.num;$('recInn').textContent='ИНН: '+state.settings.inn+' | ККТ: 00049210492';$('recDateTime').textContent=r.dateTime;
const list=$('recItemsList');list.innerHTML='';
r.items.forEach(i=>{const d=document.createElement('div');d.className='flex justify-between text-[9px]';d.innerHTML='<span>'+i.name+' ('+i.qty+'x)</span><span class="font-bold">'+(i.price*i.qty).toFixed(2)+'</span>';list.appendChild(d);});
if(r.discount>0)list.insertAdjacentHTML('beforeend','<div class="flex justify-between text-[9px] text-pink-600 font-bold"><span>СКИДКИ'+(r.promo?' ('+r.promo+')':'')+':</span><span>-'+fmt(r.discount)+' ₽</span></div>');
if(r.write>0)list.insertAdjacentHTML('beforeend','<div class="flex justify-between text-[9px] text-purple-600 font-bold"><span>БОНУСАМИ:</span><span>-'+fmt(r.write)+' ₽</span></div>');
if(r.accrual>0)list.insertAdjacentHTML('beforeend','<div class="flex justify-between text-[9px] text-emerald-600 font-bold"><span>НАЧИСЛЕНО:</span><span>+'+r.accrual+' б (баланс '+r.nb+')</span></div>');
$('recTotal').textContent=(r.total<0?'-':'')+fmt(Math.abs(r.total))+' ₽';$('recVat').textContent=fmt(r.vat)+' ₽';$('recPayType').textContent=r.payType+(r.walletPhone?' · '+r.walletPhone:'');$('recFiscal').textContent='ФД: '+r.fd+' | ФП: '+r.fp;
$('recQrImg').src=qrUrl(r.code,300);show('receiptModal');}
function renderWarehouse(){const q=($('warehouseSearch').value||'').toLowerCase();const cat=$('warehouseCategoryFilter').value;
const tb=$('warehouseTableBody');tb.innerHTML='';let tv=0;
state.products.forEach(p=>{tv+=p.price*p.stock;if(cat!=='Все'&&p.category!==cat)return;if(q&&!p.name.toLowerCase().includes(q)&&!p.code.includes(q)&&!p.barcode.includes(q))return;
let badge='<span class="px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded-full text-[9px] font-bold">В наличии</span>';if(p.stock===0)badge='<span class="px-2 py-0.5 bg-rose-100 text-rose-800 rounded-full text-[9px] font-bold">Нет</span>';else if(p.stock<=15)badge='<span class="px-2 py-0.5 bg-amber-100 text-amber-800 rounded-full text-[9px] font-bold">Мало</span>';
const tr=document.createElement('tr');tr.className='hover:bg-slate-50 border-b';
tr.innerHTML='<td class="p-2 text-slate-500">'+p.code+'</td><td class="p-2 text-slate-500">'+p.barcode+'</td><td class="p-2 font-bold">'+p.name+'</td><td class="p-2"><span class="bg-slate-100 px-1.5 rounded text-[9px] border">'+p.category+'</span></td><td class="p-2 text-right"><input type="number" step="0.01" value="'+p.price.toFixed(2)+'" onchange="updatePrice('+p.id+',this)" class="price-input"></td><td class="p-2 text-center font-bold">'+p.stock+'</td><td class="p-2 text-center">'+badge+'</td><td class="p-2 text-center"><div class="flex gap-1 justify-center"><button onclick="addStock('+p.id+')" class="px-2 py-1 bg-sky-100 text-sky-800 font-bold text-[9px] rounded border border-sky-300">+50</button><button onclick="addItem('+p.id+')" class="px-2 py-1 bg-emerald-100 text-emerald-800 font-bold text-[9px] rounded border border-emerald-300">В чек</button></div></td>';
tb.appendChild(tr);});
$('warehouseTotalValue').textContent=fmt(tv)+' ₽';}
async function updatePrice(id,input){await api('/api/product/update',{method:'POST',body:JSON.stringify({id:id,price:parseFloat(input.value)||0})});loadState();toast('💾 Цена сохранена');}
async function addStock(id){const p=prod(id);await api('/api/product/update',{method:'POST',body:JSON.stringify({id:id,stock:p.stock+50})});loadState();}
async function restockAll(){await api('/api/restock_all',{method:'POST'});loadState();toast('Склад +50');}
function openAddModal(){['apName','apCode','apBarcode','apPrice'].forEach(i=>$(i).value='');$('apStock').value='0';show('addProductModal');}
async function addProduct(){const name=$('apName').value.trim();const price=parseFloat($('apPrice').value);
if(!name||isNaN(price)||price<=0){toast('Заполните название и цену!');return;}
let code=$('apCode').value.trim();if(!code)code=String(Math.max.apply(null,state.products.map(p=>parseInt(p.code)||0))+1);
let barcode=$('apBarcode').value.trim();if(!barcode)barcode=String(Math.max.apply(null,state.products.map(p=>parseInt(p.barcode)||0))+1);
await api('/api/product',{method:'POST',body:JSON.stringify({name:name,code:code,barcode:barcode,price:price,stock:parseInt($('apStock').value)||0,unit:$('apUnit').value,category:$('apCategory').value})});
hide('addProductModal');loadState();toast('✓ Товар добавлен');}
function openCatalog(){renderCatalog();show('catalogModal');}
function renderCatalog(){const q=($('catalogModalSearch').value||'').toLowerCase();const g=$('catalogModalGrid');g.innerHTML='';
state.products.filter(p=>p.name.toLowerCase().includes(q)||p.code.includes(q)).forEach(p=>{const c=document.createElement('div');c.className='p-2.5 bg-slate-50 border rounded-lg cursor-pointer hover:border-emerald-500';c.onclick=()=>{addItem(p.id);hide('catalogModal');};
c.innerHTML='<div><span class="text-[9px] text-slate-400 font-mono-pos">Код: '+p.code+'</span><h5 class="font-bold text-xs">'+p.name+'</h5></div><div class="mt-2 flex justify-between text-xs font-mono-pos"><span class="text-emerald-700 font-bold">'+p.price.toFixed(2)+' ₽</span><span class="text-[10px] '+(p.stock>0?'bg-emerald-100 text-emerald-800':'bg-rose-100 text-rose-800')+' px-1.5 rounded font-semibold">'+(p.stock>0?'Ост:'+p.stock:'Нет')+'</span></div>';
g.appendChild(c);});}
function renderReports(){const s=state.stats;
$('repTotalRevenue').textContent=fmt(s.revenue)+' ₽';$('repChecksCount').textContent=s.checks;
$('repAvgCheck').textContent=fmt(s.checks?s.revenue/s.checks:0)+' ₽';$('repCashDrawer').textContent=fmt(s.drawer)+' ₽';
$('repSberPayVal').textContent=fmt(s.sberPay)+' ₽';$('repWalletVal').textContent=fmt(s.wallet||0)+' ₽';
const t=s.revenue||1;$('repSberPayBar').style.width=(s.sberPay/t*100)+'%';$('repWalletBar').style.width=((s.wallet||0)/t*100)+'%';
$('repReturnsVal').textContent=s.returnsSum>0?'−'+fmt(s.returnsSum)+' ₽':'';
const h=$('receiptsHistory');h.innerHTML=state.receipts.length?state.receipts.map(r=>'<div onclick=\'showReceipt(state.receipts.find(x=>x.num=="'+r.num+'"))\' class="flex gap-2 p-1.5 hover:bg-slate-50 rounded cursor-pointer border border-transparent hover:border-slate-200"><b class="font-mono-pos w-14">№'+r.num+'</b><span class="text-slate-500 flex-1">'+r.payType+(r.discount>0?' · скидка':'')+(r.accrual>0?' · +'+r.accrual+'б':'')+'</span><b class="font-mono-pos text-emerald-700">'+fmt(r.total)+' ₽</b></div>').join(''):'<i class="text-slate-400">Чеков пока нет</i>';
const rl=$('returnsList');rl.innerHTML=state.returns.length?state.returns.map(r=>'<div class="flex gap-2 p-1.5 bg-rose-50/50 rounded border border-rose-100"><b class="font-mono-pos text-rose-700 w-14">'+r.num+'</b><span class="text-slate-600 flex-1 truncate">чек №'+r.orig+' · '+r.reason+'</span><b class="font-mono-pos text-rose-700">−'+fmt(r.sum)+' ₽</b></div>').join(''):'<i class="text-slate-400">Возвратов нет</i>';
drawCharts();}
function drawCharts(){const recs=state.receipts;
const cv=$('chartHours');const ctx=cv.getContext('2d');const W=cv.width=cv.clientWidth||600;const H=cv.height=140;ctx.clearRect(0,0,W,H);
ctx.fillStyle='#334155';ctx.font='bold 11px monospace';ctx.fillText('Продажи по часам, ₽',8,14);
const by={};recs.forEach(r=>{const hh=new Date(r.ts).getHours();by[hh]=(by[hh]||0)+r.total;});
const ks=Object.keys(by).sort((a,b)=>a-b);
if(!ks.length){ctx.fillStyle='#94a3b8';ctx.fillText('Нет данных',8,60);}else{const mx=Math.max.apply(null,ks.map(k=>by[k]));const bw=Math.max(10,(W-40)/ks.length-8);
ks.forEach((k,i)=>{const bh=(by[k]/mx)*(H-56);const x=20+i*(bw+8);const y=H-26-bh;ctx.fillStyle='#21A038';ctx.fillRect(x,y,bw,bh);ctx.fillStyle='#64748b';ctx.font='9px monospace';ctx.fillText(k+'ч',x+bw/2-6,H-14);});}
const cv2=$('chartTop');const c2=cv2.getContext('2d');const W2=cv2.width=cv2.clientWidth||600;const H2=cv2.height=140;c2.clearRect(0,0,W2,H2);
c2.fillStyle='#334155';c2.font='bold 11px monospace';c2.fillText('Топ-5 товаров',8,14);
const bp={};recs.forEach(r=>r.items.forEach(i=>{bp[i.name]=(bp[i.name]||0)+i.price*i.qty;}));
const top=Object.keys(bp).map(k=>[k,bp[k]]).sort((a,b)=>b[1]-a[1]).slice(0,5);
if(!top.length){c2.fillStyle='#94a3b8';c2.fillText('Нет данных',8,60);}else{const mx=top[0][1]||1;const rh=(H2-40)/top.length;
top.forEach((p,i)=>{const y=26+i*rh;const bw=(p[1]/mx)*(W2-230);c2.fillStyle='#0284c7';c2.fillRect(190,y+3,Math.max(4,bw),rh-10);c2.fillStyle='#334155';c2.font='9px monospace';c2.fillText(p[0].substring(0,24),6,y+rh/2+2);c2.fillStyle='#0c4a6e';c2.fillText(Math.round(p[1])+'₽',194+Math.max(4,bw),y+rh/2+2);});}}
function openReturnModal(){if(!state.receipts.length){toast('Нет чеков');return;}
const s=$('retReceipt');s.innerHTML='';state.receipts.slice(0,30).forEach(r=>{const o=document.createElement('option');o.value=r.num;o.textContent='№'+r.num+' · '+r.dateTime+' · '+fmt(r.total)+' ₽';s.appendChild(o);});
onRetChange();show('returnModal');}
function onRetChange(){retCurrent=state.receipts.find(r=>r.num===$('retReceipt').value);const box=$('retItems');box.innerHTML='';
if(!retCurrent)return;
retCurrent.items.forEach((it,idx)=>{const row=document.createElement('div');row.className='flex items-center gap-2 bg-slate-50 border rounded-lg p-2';
row.innerHTML='<span class="flex-1 text-[10px] font-bold truncate">'+it.name+'</span><input type="number" min="0" max="'+it.qty+'" value="0" data-idx="'+idx+'" oninput="calcRetSum()" class="w-14 bg-white border rounded px-1 py-0.5 text-[11px] font-mono-pos text-center"><span class="text-[9px] text-slate-500">из '+it.qty+'</span>';
box.appendChild(row);});calcRetSum();}
function calcRetSum(){let sum=0;document.querySelectorAll('#retItems input').forEach(inp=>{const it=retCurrent.items[+inp.dataset.idx];const q=Math.min(Math.max(0,parseInt(inp.value)||0),it.qty);sum+=q*it.price;});$('retSum').textContent=fmt(sum)+' ₽';return sum;}
async function submitReturn(){if(calcRetSum()<=0){toast('Выберите количество!');return;}
const items=[];document.querySelectorAll('#retItems input').forEach(inp=>{const q=parseInt(inp.value)||0;if(q>0)items.push({name:retCurrent.items[+inp.dataset.idx].name,qty:q});});
const res=await api('/api/return',{method:'POST',body:JSON.stringify({num:retCurrent.num,items:items,reason:$('retReason').value})});
if(res.ok){hide('returnModal');loadState();
const r=res.ret;showReceipt({num:r.num,dateTime:r.dateTime,items:r.items,total:-r.sum,vat:r.sum*20/120,discount:0,promo:null,write:0,accrual:0,payType:'ВОЗВРАТ',fd:'—',fp:'—',code:r.code});
toast('🔄 Возврат '+r.num+' оформлен');}}
async function zReport(){if(!confirm('Снять Z-Отчет?'))return;await api('/api/zreport',{method:'POST'});loadState();toast('Z-Отчет снят');}
async function saveSettings(){await api('/api/settings',{method:'POST',body:JSON.stringify({storeName:$('cfgStoreName').value,inn:$('cfgInn').value,cashier:$('cfgCashier').value})});loadState();toast('Настройки сохранены');}
$('notesArea').value=localStorage.getItem('sbernotes')||'Смена началась в 08:00.';
function saveNotes(){localStorage.setItem('sbernotes',$('notesArea').value);toast('Заметки сохранены');}
function calcBtn(v){const d=$('calcDisplay');if(v==='C')calcExpr='';else if(v==='='){try{calcExpr=String(eval(calcExpr));}catch(e){calcExpr='Ошибка';}}else{if(calcExpr==='0'||calcExpr==='Ошибка')calcExpr='';calcExpr+=v;}d.textContent=calcExpr||'0';}
class WM{constructor(){this.ws=['posApp','warehouseApp','reportsApp','calcApp','notesApp','settingsApp'];this.z=30;this.d=null;
window.addEventListener('mousemove',e=>{if(this.d){this.d.w.style.left=(e.clientX-this.d.x)+'px';this.d.w.style.top=(e.clientY-this.d.y)+'px';}});
window.addEventListener('mouseup',()=>this.d=null);
window.addEventListener('touchmove',e=>{if(this.d){const t=e.touches[0];this.d.w.style.left=(t.clientX-this.d.x)+'px';this.d.w.style.top=(t.clientY-this.d.y)+'px';e.preventDefault();}},{passive:false});
window.addEventListener('touchend',()=>this.d=null);}
open(i){const w=$('win-'+i);w.classList.remove('minimized');this.z++;w.style.zIndex=this.z;this.tb();}
close(i){$('win-'+i).classList.add('minimized');this.tb();}
minimize(i){this.close(i);}
toggleMaximize(i){const w=$('win-'+i);if(w.dataset.max==='1'){w.style.cssText=w.dataset.prev;w.dataset.max='0';}else{w.dataset.prev=w.style.cssText;w.style.width='98vw';w.style.height='94vh';w.style.top='1vh';w.style.left='1vw';w.dataset.max='1';}}
dragStart(e,i){const w=$('win-'+i);if(w.dataset.max==='1')return;this.z++;w.style.zIndex=this.z;const p=(e.touches&&e.touches[0])||e;this.d={w:w,x:p.clientX-w.offsetLeft,y:p.clientY-w.offsetTop};}
tb(){const c=$('taskbarItems');c.innerHTML='';const L={posApp:['Касса','fa-cash-register','text-emerald-600'],warehouseApp:['Склад','fa-boxes-stacked','text-sky-600'],reportsApp:['Отчеты','fa-chart-pie','text-purple-600'],calcApp:['Кальк','fa-calculator','text-amber-600'],notesApp:['Заметки','fa-note-sticky','text-teal-600'],settingsApp:['Настр','fa-gear','text-slate-600']};
this.ws.forEach(i=>{const m=$('win-'+i).classList.contains('minimized');const b=document.createElement('button');b.className='h-8 px-2 rounded-lg border text-[10px] font-semibold flex items-center gap-1.5 shrink-0 '+(m?'bg-white border-slate-200 text-slate-600':'bg-slate-200 border-slate-300 font-bold');b.onclick=()=>m?this.open(i):this.close(i);b.innerHTML='<i class="fa-solid '+L[i][1]+' '+L[i][2]+'"></i><span class="hidden md:inline">'+L[i][0]+'</span>';c.appendChild(b);});}}
const windowManager=new WM();
window.onload=async()=>{await loadState();windowManager.tb();
setInterval(()=>{const n=new Date();$('taskbarTime').textContent=n.toLocaleTimeString('ru-RU');$('taskbarDate').textContent=n.toLocaleDateString('ru-RU');},1000);
document.addEventListener('keydown',e=>{if(e.key==='F12'){e.preventDefault();openPayment();}});
if(window.innerWidth<1024)windowManager.toggleMaximize('posApp');};
</script>
</body>
</html>'''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 80))
    print('=== Сбер POS (Amvera) ===')
    print('Домен:     https://tel-charger7772585.amvera.io')
    print('Порт:      ', port)
    print('Хранилище: ', STORAGE_MODE, DATA_FILE or '(только ОЗУ)')
    app.run(host='0.0.0.0', port=port, debug=False)
