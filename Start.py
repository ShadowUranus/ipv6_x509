# encoding: utf-8
import json
import math
import os

from PyQt5.QtCore import QTimer, QStringListModel, QThread, pyqtSignal

from CheckCert import CertInfos, init, finish
from GetCert import pool, get_certificate
from Scan_config import SuccessListRs, ScanListRs, ResListRs
from main import Ui_MainWindow
import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow

# database:
info_sql = 'INSERT INTO infos(subject_name, issuer_name, subject_rfc4514_string, issuer_rfc4514_string, CA, CRL, self_signature, serial_number, version) VALUES (?,?,?,?,?,?,?,?,?)'
error_sql = 'INSERT INTO result VALUES (?,?,?,?,?,?)'


class Checkthread(QThread):
    #  通过类成员对象定义信号对象
    _signal = pyqtSignal(str)

    def __init__(self):
        super(Checkthread, self).__init__()

    def run(self):
        lists = os.listdir('./certs/')
        all_cnt = len(lists)
        now_cnt = 0
        for f in lists:
            try:
                check = CertInfos(f)
            except FileNotFoundError:
                continue
            except Exception as e:
                print(e)
                continue
            self._signal.emit(str(math.floor(now_cnt * 100 / all_cnt)))
        self._signal.emit(str(100))
        finish()


class GetThread(QThread):
    signal = pyqtSignal(str)

    def __init__(self):
        super(GetThread, self).__init__()

    def run(self):
        file = open('websites.txt', 'a+')
        # 从redis数据库中提取更新域名信息
        try:
            new_websites = SuccessListRs.keys()
            for site in new_websites:
                file.write(site.decode() + '\n')
                SuccessListRs.delete(site)
        except:
            self.signal.emit("Redis Database Connection Failed! Pass..")
        file.seek(0)

        count = 0
        for i in file.readlines():
            count += 1
            pool.apply_async(get_certificate, args=(i.strip(), count, 443, './certs/', self.signal,))

        if count == 0:
            self.signal.emit("暂无域名信息")
        pool.close()
        pool.join()
        self.signal.emit("Finish")


class GenerateThread(QThread):
    _signal = pyqtSignal(str)

    def __init__(self):
        super(GenerateThread, self).__init__()

    def run(self):
        try:
            code = subprocess.getstatusoutput("python3 Scan_main.py")[0]
            if code == 255:
                self._signal.emit("-1")
            elif code == 250:
                self._signal.emit("Error")
        except Exception as e:
            self._signal.emit("Error")
            self._signal.emit("-1")


class ScanThread(QThread):
    _signal = pyqtSignal(str)

    def __init__(self):
        super(ScanThread, self).__init__()

    def run(self):
        try:
            code = subprocess.getstatusoutput("celery -A Scan_tasks worker")[0]
        except Exception as e:
            self._signal.emit("Error")
            self._signal.emit("-1")



class ProjectWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(ProjectWindow, self).__init__(parent)
        self.setupUi(self)
        self.file = open("config.json", "r+")
        self.timer = QTimer(self)
        self.timer2 = QTimer(self)
        self.timer3 = QTimer(self)
        self.stop_btn_1.setDisabled(True)
        self.stop_btn_2.setDisabled(True)
        self.get_certs_btn.setDisabled(True)
        self.check_cert_btn.setDisabled(True)
        self.generate_btn.setDisabled(True)
        self.start_btn.setDisabled(True)
        self.check_pgr.setValue(0)

    def loadConfig(self, ui):
        self.config = json.loads(self.file.read())
        self.file.close()
        ui.destinationHostLineEdit.setText(self.config["destHost"])
        ui.redisHostLineEdit.setText(self.config["redisHost"])
        ui.redisServicePortLineEdit.setText(self.config["redisPort"])
        ui.redisPasswordLineEdit.setText(self.config["redisPass"])
        ui.tImeoutLineEdit.setText(self.config["timeout"])

    def update_redis_status(self):
        try:
            ResListRs.keys()
            self.label_2.setText("Connected")
            self.generate_btn.setDisabled(False)
            self.start_btn.setDisabled(False)
        except:
            self.label_2.setText("Disconnected")

    def save_config(self):
        self.config["destHost"] = ui.destinationHostLineEdit.text()
        self.config["redisHost"] = ui.redisHostLineEdit.text()
        self.config["redisPort"] = ui.redisServicePortLineEdit.text()
        self.config["redisPass"] = ui.redisPasswordLineEdit.text()
        self.config["timeout"] = ui.tImeoutLineEdit.text()
        try:
            self.file = open("config.json", "w")
            self.file.write(json.dumps(self.config))
            self.file.close()
            self.save_notice.setText("Save Successfully")
            self.timer.timeout.connect(self.clean_notice)
            self.timer.start(1000 * 2)
        except Exception as e:
            self.save_notice.setText("Save Failed")
            print(e)

    def start_generate_list(self):
        self.generate_thread = GenerateThread()
        self.generate_thread._signal.connect(self.generate_call_updatelog)
        self.generate_thread.start()
        self.generate_btn.setDisabled(True)
        self.stop_btn_1.setDisabled(False)
        self.generate_thread._signal.emit("OK")

    def generate_call_updatelog(self, msg):
        if msg == "Error":
            self.label_2.setText("ERROR")
            self.generate_btn.setDisabled(False)
            self.stop_btn_1.setDisabled(True)
        elif msg == "-1":
            self.label_4.setText("主机不可达")
            self.generate_btn.setDisabled(False)
            self.stop_btn_1.setDisabled(True)
        else:
            self.label_4.setText("Generate Working")
            self.label_2.setText("Connected")
            self.timer2.setInterval(1000)
            self.timer2.timeout.connect(self.generate_update_num)
            self.timer2.start(1000)

    def generate_update_num(self):
        self.generate_note.setFontPointSize(12)
        self.generate_note.setText(str(len(ScanListRs.keys())))

    def start_scan(self):
        self.scan_thread = ScanThread()
        self.scan_thread._signal.connect(self.scan_call_updatelog)
        self.scan_thread.start()
        self.start_btn.setDisabled(True)
        self.stop_btn_2.setDisabled(False)
        self.scan_thread._signal.emit("OK")

    def scan_call_updatelog(self, msg):
        self.label_4.setText("Scan Working")
        self.timer3.setInterval(1000)
        self.timer3.timeout.connect(self.scan_update_num)
        self.timer3.start(1000)

    def scan_update_num(self):
        self.scan_note.setFontPointSize(12)
        self.scan_note.setText(str(len(ResListRs.keys())))


    def stop_generate_list(self):
        self.generate_btn.setDisabled(False)
        self.stop_btn_1.setDisabled(True)
        del self.generate_thread
        self.timer2.stop()
        self.label_4.setText("Generate Stop")

    def stop_scan(self):
        self.start_btn.setDisabled(False)
        self.stop_btn_2.setDisabled(True)
        del self.scan_thread
        self.timer3.stop()
        self.label_4.setText("Scan Stop")

    def clean_notice(self):
        self.save_notice.setText("")
        self.timer.stop()

    def load_websites(self):
        file = open('websites.txt', 'r').readlines()
        file = [x.strip() for x in file]
        names = QStringListModel()
        names.setStringList(file)
        self.HostName.setModel(names)
        self.get_certs_btn.setDisabled(False)

    def load_certs(self):
        lists = os.listdir('./certs/')
        all_certs = len(lists)
        names = QStringListModel()
        if all_certs == 0:
            names.setStringList(['certs list empty!'])
            self.CertsList.setModel(names)
        else:
            names.setStringList(lists)
            self.CertsList.setModel(names)
            self.check_cert_btn.setDisabled(False)

    def get_certs(self):
        self.get_certs_btn.setDisabled(True)
        try:
            self.get_thread = GetThread()
            self.get_thread.signal.connect(self.check_call_getlog)
            self.get_thread.start()
        except Exception as e:
            print(e)

    def check_call_getlog(self, msg):
        if msg == "Finish":
            self.get_certs_btn.setDisabled(False)
        else:
            nowText = self.get_certs_finish.toPlainText()
            self.get_certs_finish.setText(nowText + "\n" + msg)

    def check_certs(self):
        global cur
        msg = "Clean database......\n"
        self.check_notes.setText(msg)
        # Init
        init()
        msg += "Clean Done.\n"
        self.check_notes.setText(msg)

        self.check_cert_btn.setDisabled(True)
        self.check_thread = Checkthread()
        # 连接信号
        self.check_thread._signal.connect(self.check_call_backlog)  # 进程连接回传到GUI的事件
        # 开始线程
        self.check_thread.start()

        self.check_cert_btn.setDisabled(False)

    def check_call_backlog(self, msg):
        self.check_pgr.setValue(int(msg))  # 将线程的参数传入进度条
        if msg == '100':
            del self.check_thread
            self.check_notes.setText("Finish")

    def export_xls(self):
        reply = subprocess.getstatusoutput("python3 GetResults.py")[1]
        self.export_notice.setText(reply)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = ProjectWindow()
    ui.loadConfig(ui)
    ui.show()
    sys.exit(app.exec_())
