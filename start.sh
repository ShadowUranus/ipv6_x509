#!/bin/bash
while true
do
    clear
    echo "#############################################"
    echo "#                                           #"
    echo "#     X.509数字证书合规性检测系统V1.0       #"
    echo "#                                           #"
    echo "#############################################"
    echo "#                                           #"
    echo "#  1.配置修改         2.创建扫描任务        #"
    echo "#  3.执行扫描程序     4.执行证书获取        #"
    echo "#  5.执行合规性检测   6.导出检测结果        #"
    echo "#  q|Q.退出程序                             #"
    echo "#                                           #"
    echo "#############################################"
    echo ""
    
    read -p "请输入要执行的操作:" choice
    
    case $choice in
        1)
	    vim config.json
	    ;;
	2)
	    python3 Scan_main.py 2>/dev/null
	    ;;
	3)
	    celery -A Scan_tasks worker -l info
	    ;;
	4)
	    python3 GetCert.py 2>/dev/null
        ;;
	5)
            python3 CheckCert.py
	    echo "检测完毕!"
	    ;;
	6)
	    clear
	    python3 GetResults.py
	    read -p "按任意键返回..."
	    ;;
	q|Q)
	    exit
	    ;;
	*)
	    echo "输入有误，请从{1|2|3|4|q|Q}中选择"
	    ;;
    esac
    if [ $? -ne 0 ]
    then 
	echo "redis数据库连接中断"
    fi
    sleep 2
done

