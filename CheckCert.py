#!/bin/python
# -*- coding: utf-8 -*-
# Time: 2020/6/7 下午4:16

'''
证书合规性检验脚本
    检验当前目录下certs文件夹下的证书
'''
import os
import sqlite3
import re

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend

certsPath = './certs/'
reportsPath = './reports/'
con = sqlite3.connect("result.db", check_same_thread=False)
cur = con.cursor()
cur.execute("DELETE FROM infos")
cur.execute("DELETE FROM result")

info_sql = 'INSERT INTO infos(subject_name, issuer_name, subject_rfc4514_string, issuer_rfc4514_string, CA, CRL, self_signature, serial_number, version) VALUES (?,?,?,?,?,?,?,?,?)'
error_sql = 'INSERT INTO result VALUES (?,?,?,?,?,?)'
errors = 0

def init():
    cur.execute("DELETE FROM infos")
    cur.execute("DELETE FROM result")

def finish():
    con.commit()

class CertInfos:
    def __init__(self, path):
        global sql
        global errors
        self.name = path
        # 初始化错误列表
        self.error = []
        # 加载证书
        cert = open(certsPath + path, 'rb')
        self.cert = x509.load_pem_x509_certificate(cert.read(), default_backend())

        try:
            self.issue_rfc = self.cert.issuer.rfc4514_string()
            self.issue_name = self.cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception as e:
            self.issue_name = "None"
        try:
            self.subject_rfc = self.cert.subject.rfc4514_string()
            self.subject_name = self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception as e:
            self.subject_name = "None"

        if self.cert.version.__str__() == 'Version.v3':
            try:
                self.isCA = self.cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS).value.__getattribute__('ca')
                self.isCRL = self.cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.KEY_USAGE).value.__getattribute__('crl_sign')
            except:
                self.isCA = False
                self.isCRL = False
        else:
            self.isCA = False
            self.isCRL = False

        # self_signature
        try:
            if self.cert.subject.__str__() == self.cert.issuer.__str__():
                self.self_signature = 1
            else:
                self.self_signature = 0
        except Exception:
            errors += 1

        # 获取证书版本信息
        # Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
        try:
            # cryptography 可识别 Version.v1 v2 v3
            self.version = self.cert.version
        except cryptography.x509.InvalidVersion:
            cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidVersion", ""))

        # write infos
        try:
            cur.execute(info_sql, (
                self.subject_name, self.issue_name, self.subject_rfc, self.issue_rfc, int(self.isCA), int(self.isCRL),
                int(self.self_signature), str(self.cert.serial_number), str(self.version)))
            self.infos_id = cur.lastrowid
            # out_file = open("./cert_out/"+str(self.infos_id)+".pem", "wb")
            # cert.seek(0, 0)
            # out_file.write(cert.read())
            # out_file.close()

        except Exception as e:
            cur.execute(
                "SELECT id FROM infos WHERE serial_number=? and subject_rfc4514_string=? and issuer_rfc4514_string=?",
                (str(self.cert.serial_number), self.subject_rfc, self.issue_rfc))
            self.infos_id = cur.fetchall()[0][0]

        # 获取证书序列号信息
        # CertificateSerialNumber  ::=  INTEGER
        # The serial number MUST be a positive integer assigned by the CA to each certificate.
        #
        try:
            self.serial_number = self.cert.serial_number
            if self.serial_number <= 0:
                cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidSerialNumber",
                                        "The serial number MUST be a positive integer", self.infos_id))
        except Exception as e:
            cur.execute(error_sql, (
                self.name, self.subject_rfc, self.issue_rfc, "InvalidSerialNumber", e.__str__(), self.infos_id))

        # 获取有效期起始时间
        # notBefore      Time
        # Time ::= CHOICE {
        #         utcTime        UTCTime,
        #         generalTime    GeneralizedTime }
        try:
            self.not_before = self.cert.not_valid_before
        except Exception as e:
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "InvalidNotValidBefore", e.__str__(),
                         self.infos_id))
        # 获取有效期截止时间
        # notAfter       Time
        try:
            self.not_after = self.cert.not_valid_after
        except Exception as e:
            cur.execute(error_sql, (
                self.name, self.subject_rfc, self.issue_rfc, "InvalidNotValidAfter", e.__str__(), self.infos_id))
        # 获取证书颁发者信息
        try:
            self.issue = self.cert.issuer
            name_check_result = self.check_Name(self.issue)
            if name_check_result != "Pass":
                cur.execute(error_sql,
                            (self.name, self.subject_rfc, self.issue_rfc, "InvalidIssuer", name_check_result,
                             self.infos_id))
        except Exception as e:
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "InvalidIssuer", e.__str__(), self.infos_id))
        # 获取证书签名
        try:
            self.signature = self.cert.signature
            self.signature_algorithm = self.cert.signature_algorithm_oid
        except Exception as e:
            print(e)
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "InvalidSignature", e.__str__(), self.infos_id))
        # 获取证书主体
        # The issuer field MUST contain a non-empty distinguished name (DN)
        #
        try:
            self.subject = self.cert.subject
            name_check_result = self.check_Name(self.subject)
            if name_check_result != "Pass":
                cur.execute(error_sql,
                            (self.name, self.subject_rfc, self.issue_rfc, "InvalidSubject", name_check_result,
                             self.infos_id))
            if self.version.__str__() == 'Version.v3':
                try:
                    self.isCA = self.cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.BASIC_CONSTRAINTS).value.__getattribute__('ca')
                    self.isCRL = self.cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.KEY_USAGE).value.__getattribute__('crl_sign')
                except:
                    self.isCA = False
                    self.isCRL = False
            else:
                self.isCA = False
                self.isCRL = False
        except Exception as e:
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "InvalidSubject", e.__str__(), self.infos_id))
            self.isCA = False
            self.isCRL = False

        #

        # 获取 Unique Identifiers
        # 可能仅出现在版本2或者3中
        if self.version != 'Version.v1':
            try:
                self.subject_uniqueIdentifiers = self.cert.subject.get_attributes_for_oid(
                    x509.NameOID.X500_UNIQUE_IDENTIFIER)
                self.issue_uniqueIdentifiers = self.cert.issuer.get_attributes_for_oid(
                    x509.NameOID.X500_UNIQUE_IDENTIFIER)
                if self.subject.__str__() == self.issue.__str__():
                    if len(self.subject_uniqueIdentifiers) == 0 or len(self.issue_uniqueIdentifiers) == 0:
                        if not self.isCA:
                            # 建议不要在没有使用唯一标识符的不同实体间重用names
                            pass
                            # cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "UniqueIdentifiersError", "RECOMMENDS that names not be reused for different entities and that Internet certificates not make use of unique identifiers"))
                if self.isCA:
                    if len(self.subject_uniqueIdentifiers) != 0 or len(self.issue_uniqueIdentifiers) != 0:
                        # 符合本标准的CA必须不能生成带唯一标识符的证书
                        cur.execute(error_sql, (self.name, "UniqueIdentifiersError", self.subject_rfc, self.issue_rfc,
                                                "CAs conforming to this profile MUST NOT generate certificates with unique identifiers.",
                                                self.infos_id))
            except Exception as e:
                pass
        else:
            try:
                self.subject_uniqueIdentifiers = self.cert.subject.get_attributes_for_oid(
                    x509.NameOID.X500_UNIQUE_IDENTIFIER)
                self.issue_uniqueIdentifiers = self.cert.issuer.get_attributes_for_oid(
                    x509.NameOID.X500_UNIQUE_IDENTIFIER)
                cur.execute(error_sql, (self.name, "UniqueIdentifiersError", self.subject_rfc, self.issue_rfc,
                                        "Unique Identifiers fields MUST NOT appear if the version is 1", self.infos_id))
            except Exception as e:
                pass
        # 获取公钥
        # SubjectPublicKeyInfo  ::=  SEQUENCE  {
        #         algorithm            AlgorithmIdentifier,
        #         subjectPublicKey     BIT STRING  }
        try:
            self.algorithm_oid = self.cert.signature_algorithm_oid
            self.public_key = self.cert.public_key()
        except Exception as e:
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "PublicKeyError", e.__str__(), self.infos_id))
        # 获取拓展
        try:
            self.ex = self.cert.extensions
            try:
                try:
                    self.auth = self.cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                    try:
                        # CA生成的所有证书的authorityKeyIdentifier扩必须包含authorityKeyIdentifier字段(自签证书忽略)
                        self.authKey = self.cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.__getattribute__('key_identifier')
                        if self.ex.get_extension_for_oid(
                                x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).__getattribute__('critical') == True:
                            cur.execute(error_sql, (
                                self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                "Conforming CAs MUST mark AuthorityKeyIdentifier extension as non-critical",
                                self.infos_id))
                    except Exception as e:
                        if self.subject.__str__() == self.issue.__str__():
                            pass
                        cur.execute(error_sql, (
                            self.name, self.subject_rfc, self.issue_rfc, "AuthorityKeyIdentifierError", e.__str__(),
                            self.infos_id))
                except:
                    pass
                # 获取 Subject Alternative Name 拓展
                try:
                    self.subject_alt_name = self.cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    try:
                        for i in self.subject_alt_name.value:
                            if type(i) == cryptography.x509.general_name.DNSName:
                                if i.value == "":
                                    cur.execute(error_sql,
                                                (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                                 "SubjectAltName with a DNSName MUST NOT use \" \"", self.infos_id))
                            elif type(i) == cryptography.x509.general_name.IPAddress:
                                if len(i.value) != 16:
                                    cur.execute(error_sql,
                                                (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                                 "IPAddress octet string MUST contain exactly sixteen octets.",
                                                 self.infos_id))
                            elif type(i) == cryptography.x509.general_name.UniformResourceIdentifier:
                                pattern = 'http://|ftp://'
                                if not re.search(pattern, i.value):
                                    cur.execute(error_sql,
                                                (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                                 "URIs that include an authority MUST include a fully qualified domain name or IP address as the host",
                                                 self.infos_id))
                    except Exception as e:
                        pass
                except Exception as e:
                    pass

                # Issuer Alternative Name
                if self.ex.get_extension_for_oid(x509.ExtensionOID.ISSUER_ALTERNATIVE_NAME).__getattribute__('critical') == True:
                    cur.execute(error_sql, (
                        self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                        "Conforming CAs MUST mark IssuerAlternativeName extension as non-critical",
                        self.infos_id))

                # Subject Directory Attributes
                if self.ex.get_extension_for_oid(x509.ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES).__getattribute__('critical') == True:
                    cur.execute(error_sql, (
                        self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                        "Conforming CAs MUST mark SubjectDirectoryAttributes extension as non-critical",
                        self.infos_id))

                # Checking Policy Mappings
                if self.ex.get_extension_for_oid(x509.ExtensionOID.POLICY_MAPPINGS).__getattribute__('critical') == False:
                    cur.execute(error_sql, (
                        self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                        "Conforming CAs MUST mark Policy Mappings extension as critical",
                        self.infos_id))
            except:
                pass

            try:
                self.cert.extensions.get_extension_for_oid(x509.extensions.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            except Exception as e:
                if self.isCA and self.isCRL:
                    cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                            "CAs(also the CRL issuer) MUST include the distributionPoint field",
                                            self.infos_id))

            # CA 相关检测
            if self.isCA:
                if self.serial_number > 0x10000000000000000000000000000000000000000:
                    cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidSerialNumber",
                                            "Conforming CAs MUST NOT use serialNumber values longer than 20 octets",
                                            self.infos_id))
                try:
                    self.cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                    if self.ex.get_extension_for_oid(
                            x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).__getattribute__('critical') == True:
                        cur.execute(error_sql, (
                            self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                            "Conforming CAs MUST mark SubjectKeyIdentifier extension as non-critical",
                            self.infos_id))
                except:
                    cur.execute(error_sql,
                                (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                 "CA Cert MUST have SUBJECT_KEY_IDENTIFIER Extension", self.infos_id))
                try:
                    if self.cert.extensions.get_extension_for_oid(x509.ExtensionOID.POLICY_CONSTRAINTS).__getattribute__('critical') == False:
                        cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                            "Conforming CAs MUST mark policy constraints extension as critical",
                                            self.infos_id))
                except Exception as e:
                    cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                            "Conforming CAs MUST mark policy constraints extension as critical",
                                            self.infos_id))

                try:
                    pathLen = self.cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.BASIC_CONSTRAINTS).value.__getattribute__('path_length')
                    if pathLen is not None and pathLen < 0:
                        cur.execute(error_sql, (self.name, self.subject_rfc, self.issue_rfc, "InvalidExtension",
                                                "The pathLenConstraint field MUST be greater than or equal to zero",
                                                self.infos_id))
                except:
                    pass



        except cryptography.x509.DuplicateExtension as e:  # 在证书中找到多个相同类型的扩展名
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "DuplicateExtension", e.__str__(), self.infos_id))
        except cryptography.x509.UnsupportedGeneralNameType as e:  # 扩展名包含不受支持的通用名称
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "UnsupportedGeneralNameType", e.__str__(),
                         self.infos_id))
        except UnicodeError as e:  # 扩展包含的IDNA编码无效或与IDNA 2008不兼容
            cur.execute(error_sql,
                        (self.name, self.subject_rfc, self.issue_rfc, "UnicodeError", e.__str__(), self.infos_id))
        except Exception as e:
            print(e)

    def check_Name(self, name):
        if len(name.rfc4514_string()) == 0:
            return "Name field MUST contain a non-empty DN"
        C = name.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
        if len(C) > 0 and len(C[0].value) != 2:
            return "Country name must be a 2 character country code"
        return "Pass"


if __name__ == '__main__':
    lists = os.listdir(certsPath)
    count = 0
    all_certs = len(lists)
    if all_certs == 0:
        print("暂无证书")
        exit(-1)
    for f in lists:
        count += 1
        try:
            check = CertInfos(f)
        except FileNotFoundError:
            continue
        except Exception as e:
            # print("Error: ", e)
            continue
        print("Complete %s/%s" % (count, all_certs))
    con.commit()
    cur.close()

