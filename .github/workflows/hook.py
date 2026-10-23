#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""非GKI(4.19)手动hook注入器：向fs/exec.c、fs/open.c、fs/read_write.c插入KSU调用点。
失败自动回滚并退出1，workflow会回退kprobes模式。"""
import os
import re
import shutil
import sys

FILES = ['fs/exec.c', 'fs/open.c', 'fs/read_write.c']
KSU_DIR = 'drivers/kernelsu'


def sym(name):
    for root, dirs, files in os.walk(KSU_DIR):
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            if f.endswith(('.c', '.h')):
                try:
                    with open(os.path.join(root, f), encoding='utf-8', errors='ignore') as fh:
                        if name in fh.read():
                            return True
                except OSError:
                    pass
    return False


HAS_EXEC = sym('ksu_handle_execveat')
HAS_EXEC2 = sym('ksu_handle_execveat_sucompat')
HAS_FAC = sym('ksu_handle_faccessat')
HAS_FAC2 = sym('ksu_handle_faccessat_2')
print('[hooks] 符号检测: execveat=%s sucompat=%s faccessat=%s faccessat_2=%s'
      % (HAS_EXEC, HAS_EXEC2, HAS_FAC, HAS_FAC2))


def load(p):
    with open(p, encoding='utf-8', errors='surrogateescape') as f:
        return f.read()


def save(p, s):
    with open(p, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(s)


def find_pos(src, start, pattern):
    m = re.search(pattern, src[start:])
    if not m:
        return -1
    return start + m.end()


def insert_after(src, pos, code):
    nl = src.find('\n', pos)
    if nl < 0:
        nl = len(src) - 1
    return src[:nl + 1] + code + src[nl + 1:]


def insert_after_first_blank(src, body_start, code):
    idx = src.find('\n\n', body_start)
    if idx < 0:
        return None
    return src[:idx + 2] + code + src[idx + 2:]


def hook_exec():
    p = 'fs/exec.c'
    src = load(p)
    if 'ksu_handle_execveat' in src:
        print('[hooks] exec.c: 已有hook，跳过')
        return True
    m = re.search(r'static\s+int\s+(do_execveat_common|__do_execve_file)\s*\(', src)
    if not m:
        print('[hooks] exec.c: 未找到目标函数')
        return False
    fn = m.group(1)
    sig = src[m.start():src.find('{', m.end())]
    if 'struct filename *filename' not in sig:
        print('[hooks] exec.c: %s形参异常，需人工适配' % fn)
        return False
    fd = 'fd' if re.search(r'\bint\s+fd\b', sig) else None
    flags = 'flags' if re.search(r'\bint\s+flags\b', sig) else None
    argv = '__argv' if '__argv' in sig else 'argv'
    envp = '__envp' if '__envp' in sig else 'envp'
    if not fd or not flags:
        print('[hooks] exec.c: 形参识别失败')
        return False
    ext = '#ifdef CONFIG_KSU\n'
    if HAS_EXEC:
        ext += ('extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n'
                '\t\t\tvoid *envp, int *flags);\n')
    if HAS_EXEC2:
        ext += ('extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,\n'
                '\t\t\tvoid *argv, void *envp, int *flags);\n')
    ext += '#endif\n\n'
    call = '#ifdef CONFIG_KSU\n'
    if HAS_EXEC:
        call += '\tksu_handle_execveat(&%s, &filename, &%s, &%s, &%s);\n' % (fd, argv, envp, flags)
    if HAS_EXEC2:
        call += '\tksu_handle_execveat_sucompat(&%s, &filename, &%s, &%s, &%s);\n' % (fd, argv, envp, flags)
    call += '#endif\n'
    if not HAS_EXEC and not HAS_EXEC2:
        print('[hooks] exec.c: 没有任何可用符号')
        return False
    src = src[:m.start()] + ext + src[m.start():]
    pos = find_pos(src, m.start(), r'if \(IS_ERR\(filename\)\)[^\n]*\n\s*return\s+PTR_ERR\(filename\);')
    if pos >= 0:
        src = insert_after(src, pos, call)
        print('[hooks] exec.c OK (标准锚点)')
    else:
        out = insert_after_first_blank(src, src.find('{', m.start()), call)
        if out is None:
            print('[hooks] exec.c: 插入点未找到')
            return False
        src = out
        print('[hooks] exec.c OK (兜底锚点)')
    save(p, src)
    return True


def hook_open():
    p = 'fs/open.c'
    src = load(p)
    if 'ksu_handle_faccessat' in src:
        print('[hooks] open.c: 已有hook，跳过')
        return True
    m = re.search(r'static\s+(?:long|int)\s+do_faccessat\s*\(', src)
    if not m:
        print('[hooks] open.c: 未找到do_faccessat')
        return False
    sig = src[m.start():src.find('{', m.end())]
    if 'const char __user' not in sig:
        print('[hooks] open.c: 形参异常，需人工适配')
        return False
    if HAS_FAC:
        ext = ('#ifdef CONFIG_KSU\n'
               'extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n'
               '\t\t\tint *mode);\n'
               '#endif\n\n')
        call = ('#ifdef CONFIG_KSU\n'
                '\tksu_handle_faccessat(&dfd, &filename, &mode);\n'
                '#endif\n')
    elif HAS_FAC2:
        ext = ('#ifdef CONFIG_KSU\n'
               'extern int ksu_handle_faccessat_2(int *dfd, const char __user **filename_user,\n'
               '\t\t\tint *mode, int *flags);\n'
               '#endif\n\n')
        call = ('#ifdef CONFIG_KSU\n'
                '\t{\n'
                '\t\tint ksu_flags = 0;\n'
                '\t\tksu_handle_faccessat_2(&dfd, &filename, &mode, &ksu_flags);\n'
                '\t}\n'
                '#endif\n')
    else:
        print('[hooks] open.c: 没有任何faccessat符号')
        return False
    src = src[:m.start()] + ext + src[m.start():]
    pos = find_pos(src, m.start(), r'if \(mode & ~S_IRWXO\)[^\n]*\n\s*return\s+-EINVAL;')
    if pos >= 0:
        src = insert_after(src, pos, call)
        print('[hooks] open.c OK (标准锚点)')
    else:
        out = insert_after_first_blank(src, src.find('{', m.start()), call)
        if out is None:
            print('[hooks] open.c: 插入点未找到')
            return False
        src = out
        print('[hooks] open.c OK (兜底锚点)')
    save(p, src)
    return True


def hook_read():
    p = 'fs/read_write.c'
    src = load(p)
    if 'ksu_handle_vfs_read' in src:
        print('[hooks] read_write.c: 已有hook，跳过')
        return True
    m = re.search(r'\nssize_t\s+vfs_read\s*\(', src)
    if not m:
        print('[hooks] read_write.c: 未找到vfs_read')
        return False
    st = m.start() + 1
    ext = ('#ifdef CONFIG_KSU\n'
           'extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,\n'
           '\t\t\tsize_t *count_ptr, loff_t **pos);\n'
           '#endif\n\n')
    call = ('#ifdef CONFIG_KSU\n'
            '\tksu_handle_vfs_read(&file, &buf, &count, &pos);\n'
            '#endif\n')
    src = src[:st] + ext + src[st:]
    pos = find_pos(src, st, r'if \(!\(file->f_mode & FMODE_READ\)\)\s*\n\s*return\s+-EBADF;')
    if pos >= 0:
        src = insert_after(src, pos, call)
        print('[hooks] read_write.c OK (标准锚点)')
    else:
        out = insert_after_first_blank(src, src.find('{', st), call)
        if out is None:
            print('[hooks] read_write.c: 插入点未找到')
            return False
        src = out
        print('[hooks] read_write.c OK (兜底锚点)')
    save(p, src)
    return True


def main():
    missing = [f for f in FILES if not os.path.exists(f)]
    if missing:
        print('[hooks] 缺少文件: %s' % missing)
        sys.exit(1)
    for f in FILES:
        if not os.path.exists(f + '.ksuorig'):
            shutil.copy(f, f + '.ksuorig')
    ok = True
    for fn in (hook_exec, hook_open, hook_read):
        try:
            if not fn():
                ok = False
        except Exception as e:
            print('[hooks] 异常: %r' % e)
            ok = False
    if not ok:
        for f in FILES:
            if os.path.exists(f + '.ksuorig'):
                shutil.copy(f + '.ksuorig', f)
        print('[hooks] 失败，已回滚(将回退kprobes模式)')
        sys.exit(1)
    print('[hooks] 三处手动hook全部注入成功')


if __name__ == '__main__':
    main()
