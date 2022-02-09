import sys

from lxml import etree
import requests


def request_cve(keyword, filename):
    # 要爬取的url，注意：在开发者工具中，这个url指的是第一个url
    url = "http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=%s" % keyword

    # 模仿浏览器的headers
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    }

    # get请求，传入参数，返回结果集
    resp = requests.get(url, headers=headers)
    # 将结果集的文本转化为树的结构
    tree = etree.HTML(resp.text)

    # 获取CVE数量
    num = tree.xpath("/html/body/div[1]/div[3]/div[1]/b/text()")
    num = num[0]
    print("%s cve num: %s" % (keyword, num))

    cvelist = []
    for s in range(1,int(num) + 1):
        #根据树的路径找到对应的数据集
        cve_name = tree.xpath("/html/body/div[1]/div[3]/div[2]/table/tr["+str(s)+"]/td[1]/a/text()")
        # #获取数据集中的元素
        cvelist.append(cve_name[0])

    with open("%s" % filename, "a+") as f:
        for cve in cvelist:
            f.write(cve + "\n")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: python request_cve.py keyword filename")
    keyword = sys.argv[1]
    filename = sys.argv[2]
    request_cve(keyword, filename)