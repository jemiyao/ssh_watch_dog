#!/usr/bin/env python3
# coding=utf8
import logging
import os
import configparser
import paramiko
from flask import Flask, request, jsonify


def log_inst():
    lg = logging.getLogger('ssh_watch_dog')
    lg.setLevel(logging.DEBUG)
    user_home = os.path.expanduser('~')
    usr_log_handler = logging.FileHandler(os.path.join(user_home, f'ssh_watch_dog.log'))
    ch_formatter = logging.Formatter('%(name)s %(asctime)s {%(levelname)s}:%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    usr_log_handler.setFormatter(ch_formatter)
    lg.addHandler(usr_log_handler)
    # 添加一个将日志输出到控制台的处理程序
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    # 设置日志记录器的格式
    console_handler.setFormatter(ch_formatter)
    # 将处理程序添加到日志记录器
    lg.addHandler(console_handler)
    return lg


logger = log_inst()
app = Flask(__name__)


def ssh_connect(conf):
    host = conf['host']
    user = conf['user']
    port = conf['port']
    password = conf.get('password')
    auth_key = conf.get('auth-key')
    logger.info(f'host: {host}, user: {user}, port: {port}, password: {password}, auth_key: {auth_key}')
    # 创建一个SSH客户端
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # 连接到SSH服务器
    ssh.connect(host, username=user, password=password, port=port, key_filename=auth_key)
    return ssh


def run_command(section, ssh, command):
    logger.info(f'{section} command: {command}')
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    if error:
        logger.error(f"Error: {error}")
    if output:
        logger.debug(f"{section}: {output}")
    ssh.close()
    return output


@app.route('/stat', methods=['GET'])
def ssh_stat():
    conf_path = "ssh_wd.ini.template"
    if not os.path.exists(conf_path):
        conf_path = f"{os.path.expanduser('~')}/.watchdog/{conf_path}"
        if not os.path.exists(conf_path):
            logger.error("config file not found in path (ssh_wd.ini.template or ~/.watchdog/ssh_wd.ini.template)")
            return "config error", 500

    config_reader = configparser.ConfigParser()
    config_reader.read(conf_path)

    name = request.args.get("name", "")
    if name == '':
        ssh_proxy = config_reader.sections()
        res = {}
        for section in ssh_proxy:
            try:
                logger.info(f"section: {section}")
                ssh_conf = config_reader[section]
                ssh = ssh_connect(ssh_conf)
                out = run_command(section, ssh, "echo -n 'ok'")
                if out == 'ok':
                    res[section] = out
                else:
                    res[section] = "fail"
            except Exception as e:
                res[section] = f"{e}"
                logger.error(f"{section} error: {e}")
        return jsonify(res), 200
    else:
        logger.info(f"section: {name}")
        try:
            ssh_conf = config_reader[name]
            ssh = ssh_connect(ssh_conf)
            out = run_command(name, ssh, "echo -n 'ok'")
            if out == 'ok':
                return jsonify({"status": "error", "msg": out}), 500
            else:
                return jsonify({"status": "ok"}), 200
        except Exception as e:
            logger.error(f"{name} error: {e}")
            return jsonify({"status": "error", "msg": f"{e}"}), 500


if __name__ == '__main__':
    app.run(debug=True)
