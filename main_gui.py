import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel
)
from PyQt5.QtCore import QProcess, Qt
from PyQt5.QtGui import QFont

class AttackDetectionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SemiGuard")
        self.setGeometry(100, 100, 900, 650)
        self.setStyleSheet("background-color: #FFF3E0; color: #212121;")

        self.layout = QVBoxLayout()

        self.titleLabel = QLabel("Network Attack Detection Panel")
        self.titleLabel.setAlignment(Qt.AlignCenter)
        self.titleLabel.setFont(QFont("Arial", 20, QFont.Bold))
        self.titleLabel.setStyleSheet("""
            color: #FF9800;
            margin-bottom: 20px;
        """)
        self.layout.addWidget(self.titleLabel)

        self.outputBox = QTextEdit()
        self.outputBox.setReadOnly(True)
        self.outputBox.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                color: #BF360C;
                border: 1px solid #FFAB40;
                font-family: Consolas;
                font-size: 14px;
                padding: 10px;
            }
        """)
        self.layout.addWidget(self.outputBox)

        self.startButton = QPushButton("🟠 Start Detection")
        self.startButton.setFont(QFont("Arial", 14))
        self.startButton.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                padding: 10px 20px;
                border-radius: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FB8C00;
            }
        """)
        self.startButton.clicked.connect(self.run_scripts)
        self.layout.addWidget(self.startButton)

        self.setLayout(self.layout)
        self.processes = []

    def append_output(self, text):
        self.outputBox.append(text)

    def run_scripts(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        scripts = [
            "arp_spoof_detection.py",
            "ddos_attack_detection.py",
            "brute_force_attack_detection.py",
            "icmp_attack_detection.py"
        ]

        for script in scripts:
            script_path = os.path.join(base_dir, script)
            if os.path.exists(script_path):
                process = QProcess(self)
                process.setProgram("python3")
                process.setArguments([script_path])
                process.readyReadStandardOutput.connect(
                    lambda p=process: self.append_output(p.readAllStandardOutput().data().decode())
                )
                process.readyReadStandardError.connect(
                    lambda p=process: self.append_output(p.readAllStandardError().data().decode())
                )
                process.start()
                self.processes.append(process)
            else:
                self.append_output(f"[❌ ERROR] File not found: {script_path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AttackDetectionApp()
    window.show()
    sys.exit(app.exec_())
