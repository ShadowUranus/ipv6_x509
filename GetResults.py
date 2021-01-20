# encoding: utf-8
import sqlite3
import csv

con = sqlite3.connect("result.db")
cur = con.cursor()

query_all_sql = "SELECT COUNT(*) FROM result"
query_distinct_cert_sql = "SELECT COUNT(*) FROM infos;"
query_distinct_error_sql = "SELECT COUNT(*) FROM (SELECT DISTINCT cert_id, error_type, error_detail FROM result)"
query_error_type = "select error_type, count(*) from (select distinct cert_id, error_type, error_detail from result) group by error_type"

if __name__ == '__main__':
    cur.execute(query_all_sql)
    number = cur.fetchone()[0]
    print("总违规数量:")
    print(number)
    cur.execute(query_distinct_cert_sql)
    number = cur.fetchone()[0]
    print("违规证书(去重)数量:")
    print(number)
    cur.execute(query_distinct_error_sql)
    number = cur.fetchone()[0]
    print("违规数量(去重):")
    print(number)
    cur.execute(query_error_type)
    items = cur.fetchall()
    if items is not None:
        print("违规类型:")
        for item in items:
            print("{}:{}".format(item[0], item[1]))

    csvWriter = csv.writer(open("output.csv", "w"))
    query_sql = "SELECT file_name, subject_rfc4514_string, issuer_rfc4514_string, error_type, error_detail FROM result"
    cur.execute(query_sql)
    all = cur.fetchall()
    csvWriter.writerows(all)
    print("结果已导出至output.csv")
