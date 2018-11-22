import requests
import re
from bs4 import BeautifulSoup
import urllib
import xlsxwriter
import threading

# class myThread(threading.Thread):
#     def __init__(self, html):
#         threading.Thread.__init__(self)
#         self.html = html
#     data = []
#     def run(self):
#         self.data = parsePage(self.html)
#
#     def get_data(self):
#         return self.data

def generateURL(good, pages=5):
    url_str = urllib.parse.quote(good)
    urls = ("https://search.jd.com/Search?keyword={}&enc=utf-8&qrst=1&rt=1&stop=1&vt=2&offset=4&page={}&s=1&click=0".format(url_str, i) for i in range(1, pages*2, 2))
    return urls


def get_html(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
            'ContentType': 'text/html; charset=utf-8',
            'Accept-Encoding': 'gzip, deflate, sdch',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'Connection': 'keep-alive'
        }
        html = requests.get(url, headers=headers, timeout=30)
        html.encoding = html.apparent_encoding
        return html
    except:
        return '获取HTML失败'


def parsePage(html):
    soup = BeautifulSoup(html.text, 'lxml')
    titles = soup.find_all(class_="p-name p-name-type-2")
    prices = soup.find_all(class_="p-price")
    commits = soup.find_all(class_="p-commit")
    imgs = soup.find_all(class_="p-img")
    shop = soup.find_all(class_="curr-shop")

    return zip(titles, prices, commits, imgs, shop)


def createListHeader(workbook):
    worksheet = workbook.add_worksheet()
    bold = workbook.add_format({'bold': True, 'font_color': 'red'})
    worksheet.write('A1', '标题', bold)
    worksheet.write('B1', '店铺', bold)
    worksheet.write('C1', '价格', bold)
    worksheet.write('D1', '评价', bold)
    worksheet.write('E1', '链接', bold)

    # 设置列宽度
    worksheet.set_column('A:A', 120)
    worksheet.set_column('B:B', 16)
    worksheet.set_column('C:C', 8)
    worksheet.set_column('D:D', 16)
    worksheet.set_column('E:E', 30)

    return worksheet


def storeGoodsList(data_, worksheet, row=1):
    col = 0

    for title, price, commit, img, shop in data_:
        res_price = re.match('^(￥\d+)', price.text.strip())  # 去除多余￥
        res_shop = re.match('^<a.+title="(.+)">', str(shop))
        data = {
            'title' :   title.text.strip().split('\n')[0],
            'price' :   res_price.group(1),
            'commit':   '已有' + commit.text.strip(),
            'link'  :   'https:' + img.find_all('a')[0].get("href").split(';')[0],
            'shop'  :   res_shop.group(1)
        }
        worksheet.write(row, col, data['title'])
        worksheet.write(row, col+1, data['shop'])
        worksheet.write(row, col+2, data['price'])
        worksheet.write(row, col+3, data['commit'])
        worksheet.write(row, col+4, data['link'])
        row += 1


def main(good, pages):
    workbook = xlsxwriter.Workbook(good +  '.xlsx')  # 创建表
    worksheet = createListHeader(workbook)
    urls = generateURL(good, pages=pages)       # 生成URLs
    row = 1                                     # 第一行开始写入
    print("开始爬取京东商品信息")
    for url in urls:
        try:
            html = get_html(url)
            data = parsePage(html)
            print("正在爬取第 "+str(row//25+1)+" 页内容")
            storeGoodsList(data, worksheet, row)
            print("存储成功")
            row += 25
        except:
            print(url, " 页面出错")
            continue

    try:
        workbook.close()
        print("爬取结束")
    except:
        print("\n-------------------文档关闭失败----------------\n")
        print("--------------请先关闭 Excel 再重新爬取--------")


if __name__ == '__main__':
    good = input("请输入要查询的商品：\n")
    pages = int(input("请输入要查询的页数：\n"))
    main(good, pages)