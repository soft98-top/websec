# 1-Basis Command Line

## man

用于查询命令的手册，最基本的指令，基本使用方法 man 指令、man -k 指令关键词、man 指令级别 指令。

## apropos

用户用关键词查询指令== man -k，使用方法 apropos 指令关键词。

## ls

文件清单，用于列出当前目录下的文件详情。基本使用方法 ls 、列出所有文件加相应信息 ls -al。

## cd

改变当前目录，常规使用方法 cd 绝对路径、cd 相对路径、返回用户主目录 cd ~。

## pwd

显示当前目录。

## mkdir

创建目录，常规用法 mkdir 新目录名[,新目录名2]，从父目录开始创建mkdir -p 父目录/{子目录1,子目录2}

## which

用于在$PATH中定义的位置进行搜索，一般用于定位命令。例如 which bash。

## locate

这个实在一个本地的数据库中进行搜索，这个数据库定时更新，但是比较新操作的可能不能及时被更新，所以建议每次搜索前先自己更新一下。先用 sudo updatedb，然后用 locate 文件名。

## find

应该说是最强大和复杂的搜索了，内容很多，常用指令 find 目录名 -name 文件名表达式

## SSH 服务

启动 sudo systemctl start ssh

开机自启动 sudo systemctl enable ssh

关闭 sudo systemctl stop ssh

查看服务 sudo ss -antlp | grep sshd

## HTTP 服务

启动 sudo systemctl start apache2

开机自启动 sudo systemctl enable apache2

关闭 sudo systemctl stop apache2

查看服务 sudo ss -antlp | grep apache

## 查看系统服务列表

systemctl list-unit-files

## 更新文件列表

sudo apt update

## 升级软件

sudo apt upgrade

如果要更新指定软件，后面跟随软件名字

## 更新软件依赖

sudo apt dist-upgrade

## 软件库搜索

apt-cache search 关键词

apt show 软件名

apt show用来显示软件的相关介绍

## 软件安装

sudo apt install 软件名

## 软件卸载

sudo apt remove --purge 软件名

--purge 用于完全卸载，会将用户配置文件也删除。