#端口扫描程序功能介绍

![端口扫描程序界面][img/img.png]


- 程序支持多端口扫描，默认扫描端口0~65535，可以通过文本框更改端口扫描范围。
- 程序支持多网段扫描，默认扫描第四位主机号的范围为0~255，可以通过文本框更改网段扫描范围。
- 程序支持TCP Connect扫描、TCP SYN扫描、TCP FIN扫描、TCP NULL扫描、TCP XMAS扫描、UDP扫描。通过扫描方式点选框选择扫描方式，其中TCP FIN扫描、TCP NULL扫描、TCP XMAS扫描只支持扫描Linux系统下的网络端口。
- 程序能输出扫描状态。输出结果是由地址、端口号、端口状态、扫描方式组成的四元组，能根据用户选择显示开放或关闭端口，能清空已经保存和显示在文本框中的结果。
- 所有扫描方式都已经加入多线程，较大提升了端口扫描速度。

#运行环境
>Python 3.7


#使用方法
>main.py为主要实现代码，scan_ui.py为pyqt5生成的界面代码，requirements.txt为运行需要的库。