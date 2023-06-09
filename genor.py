# @author Xu.Cao
# @date   2023-04-17
# @detail 当前代码负责对行为的日志进行去重、合法化以及找到图中的环；
#         目标是生成一个基础的可以区分各种行为的状态机，当前的状态机
#         可能还较为复杂，需要人工进行进一步修改和更正
#
# @history
#       <author>    <time>      <version>           <description>
#       Xu.Cao      2023-04-17  0.0.1               创建了本文件
#       Xu.Cao      2023-05-09  1.2.3               1. 修改底层架构，修改分析日志的格式，图库微调
#                                                   2. 移除 exit_group以其他方式到达行为结尾
#                                                   3. 修改寻找环的方法，先找小环，保留所有可能的环

from graphviz import Digraph
import os


# 用于表示一条边的信息，保存了一个用于区分不同边的 key 和实际命令 command
# @member key 用于区分不同的边
# @member command 该边代表的实际动作，系统调用 + 相关参数
# @method __hash__, __eq__ 的重写使得本类可以正确的用于哈希集合类的键
class Edge:
    def __init__(self, key_: str, command_: str):
        self.key = key_  # 用于计算哈希的键
        self.command = command_  # command 存储实际执行的系统调用即参数

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__hash__() == other.__hash__()
        else:
            return False


# 用于记录图或者树的节点
# @member id 当前节点的编号
# @member children 事件到子图的字典
class TreeNode:
    def __init__(self, id_: str):
        self.id = id_  # 当前节点的编号
        self.is_leaf = False
        self.children = dict()  # 存储子图，事件 => 状态机子图


# 获取日志文件中的系统调用序列
# @return 一个列表，每一个元素都是一个进程的系统调用序列
def get_log_list(folder_name_: str) -> list:
    log_list_ = []
    file_list_ = [file_ for file_ in os.listdir(folder_name_) if os.path.isfile(os.path.join(folder_name_, file_))]
    for file_ in file_list_:
        # 文件名即为命令，保存命令并添加到操作序列的最后作为最终结果
        cmd_ = file_.replace('_', ' ')
        with open(os.path.join(folder_name_, file_)) as f_:
            content_ = f_.readlines()
        content_ = [content_[i].strip().split() for i in range(len(content_)) if
                    (i == 0 or content_[i] != content_[i - 1]) and content_[i].strip() != ''
                    and content_[i].split()[2] == cmd_.split()[0]]
        content_ = validate_branch(content_)
        content_.append(cmd_)
        log_list_.append(content_)
    return log_list_


# 规范化进程的系统调用序列，去除不合法的序列，如在没有打开 fd 的情况下 read
# 在规范化的同时，减少连续的读写调用，这对状态机没有帮助
# @param  syscall_list_ 进程对应的系统调用序列
# @return 返回一个新的列表，包含没有逻辑错误的系统调用序列
def validate_branch(syscall_list_: list) -> list:
    fd_sets_ = set()
    is_read_, is_write_ = False, False

    valid_syscall_list_ = list()
    for item in syscall_list_:
        if item[3] in ['openat', 'socket']:
            fd_sets_.add(item[5])
        elif item[3] in ['read', 'write', 'close', 'connect'] and item[5] not in fd_sets_:
            continue
        elif item[3] == 'close':
            fd_sets_.remove(item[5])
        elif item[3] == 'dup3':
            fd_sets_.add(item[6])

        # 记录 read 和 write
        if item[3] == 'read':
            if is_read_:
                continue
            is_read_ = True
        elif item[3] == 'write':
            if is_write_:
                continue
            is_write_ = True
        else:
            # 如果都不是，那就重置标志
            is_read_, is_write_ = False, False

        valid_syscall_list_.append(item)
    valid_syscall_list_ = [valid_syscall_list_[i] for i in range(len(valid_syscall_list_)) if
                           (i == 0 or valid_syscall_list_[i] != valid_syscall_list_[i - 1])]
    return valid_syscall_list_


# 对系统调用序列进行编号，相同的操作（如 openat 系统调用并使用相同的打开方式）编号相同
# @param  syscall_list_ 进程对应的系统调用序列，需要是合法序列
# @return 返回系统调用序列对应的编号序列
# @see    {@code validate_branch}
def number_the_branch(syscall_list_: list) -> list:
    syscall_id_list_ = list()
    syscall_args_sets_ = dict()
    syscall_args_id_ = 0

    for line in syscall_list_:
        syscall_args_ = get_trigger(line)

        if syscall_args_ not in syscall_args_sets_:
            syscall_args_sets_.update({syscall_args_: syscall_args_id_})
            syscall_args_id_ += 1
        syscall_id_list_.append(syscall_args_sets_.get(syscall_args_))

    return syscall_id_list_


# 找到图中存在的环并返回一个合法的系统调用序列，还有如何成环的列表
# @param  syscall_list_ 一个进程的系统调用序列
# @return 返回一个成环的点组成的列表
def find_loop_of_branch(valid_syscall_list_: list) -> dict:
    syscall_id_list_ = number_the_branch(valid_syscall_list_)

    sub_list_cnt_ = list()
    len_ = len(syscall_id_list_)
    start_, end_ = 1, len_ - 2
    while start_ < end_:

        max_len_ = min(start_ + 1, len_ - start_ - 1)
        try_len_ = 1
        while try_len_ <= max_len_:
            left_ = syscall_id_list_[start_ - try_len_ + 1: start_ + 1]
            right_ = syscall_id_list_[start_ + 1: start_ + try_len_ + 1]
            if left_ == right_ and valid_syscall_list_[start_ + 1][3] == 'openat':
                sub_list_cnt_.append((start_ - try_len_ + 1, start_ + 1))
                break
            try_len_ += 1

        start_ += 1

    # # 找循环区间最大的
    # max_loop_len_ = 0
    # for i in sub_list_cnt_:
    #     max_loop_len_ = max(max_loop_len_, i[1] - i[0])
    # sub_list_cnt_ = list(filter(lambda x: x[1] - x[0] == max_loop_len_, sub_list_cnt_))

    # 剩余的循环说明是对不同目标文件的相同操作
    go_back_ = dict()  # 用来保存跳回到哪里，即如何循环
    if len(sub_list_cnt_) >= 1:
        go_back_.update({sub_list_cnt_[0][1]: sub_list_cnt_[0][0]})
    for i in range(1, len(sub_list_cnt_)):
        if sub_list_cnt_[i][0] == sub_list_cnt_[i - 1][1]:
            go_back_.update({sub_list_cnt_[i][1]: go_back_.get(sub_list_cnt_[i][0])})
        else:
            go_back_.update({sub_list_cnt_[i][1]: sub_list_cnt_[i][0]})

    return go_back_


# 根据所有进程的系统调用列表和成环的保存点列表，并返回一棵最初始的状态机构成的图的数据结构
# v1.2.1 移除 exit_group（特殊情况除外），以其他方式到达行为结尾 (Xu.Cao)
#
# @param  syscall_lists_ 所有进程的系统调用合法序列
# @param  go_backs_ 当前节点应该指向的节点，从而构成环
# @return 返回初始的状态机构成的图数据结构
def get_tree(syscall_lists_: list, go_backs_: list) -> TreeNode:
    node_id_ = 1
    tree_ = TreeNode('0')

    for i in range(len(syscall_lists_)):
        state_ = tree_
        syscall_list_ = syscall_lists_[i]
        go_back_ = go_backs_[i]
        save_points = dict()

        for j in range(len(syscall_list_)):
            line_ = syscall_list_[j]
            key_ = get_trigger(line_)
            sys_call_args_ = get_label(line_)

            edge_ = Edge(key_, sys_call_args_)
            if state_.children.get(edge_) is None:
                if j == len(syscall_list_) - 1:
                    leaf_ = TreeNode(str(node_id_))
                    node_id_ += 1
                    state_.children.update({edge_: leaf_})
                    leaf_.children = line_[2]
                    break
                else:
                    if j in go_back_:
                        state_.children.update({edge_: save_points[go_back_[j]]})
                    else:
                        state_.children.update({edge_: TreeNode(str(node_id_))})
                        node_id_ += 1
            state_ = state_.children[edge_]
            if isinstance(state_.children, str):
                break

            if j in go_back_.values():
                save_points.update({j: state_})

    return tree_


# 简化树的结构，将只有单个节点的分支删除
def simplify_tree(tree: dict) -> dict:
    for k, v in tree.items():

        while isinstance(tree[k], dict) and len(tree[k]) == 1:
            if list(tree[k].keys())[0][:6] in ['openat', 'socket']:
                break
            tree[k] = list(tree[k].values())[0]

        if isinstance(tree[k], str):
            continue

        simplify_tree(tree[k])

    return tree


state_transition_table = list()
vis = set()


# 保存并显示树形图形
# @param tree 要显示的树形的结构
def show_tree(tree_: TreeNode) -> None:
    g_ = Digraph('state machine', filename='state_machine', format='png', strict=False)

    g_.node('0', '0')
    vis.add(tree_)
    build_tree(g_, tree_)
    g_.view()


# 递归构建图
# @param g_ 将图形绘制到 g_ 上
# @param tree_ 当前子图结构，绘制当前子图根节点到所有子节点之间的边
def build_tree(g_: Digraph, tree_: TreeNode) -> None:
    global state_transition_table

    root_id = tree_.id
    for k, v in tree_.children.items():
        if isinstance(v.children, str):
            g_.node(v.id, v.children)
            g_.edge(root_id, v.id, k.command)
            state_transition_table.append("{} {} {}".format(root_id, k.key, v.children))
        else:
            if id(v) not in vis:
                g_.node(v.id, v.id)
                g_.edge(root_id, v.id, k.command)
                vis.add(id(v))
                build_tree(g_, v)
                state_transition_table.append("{} {} {}".format(root_id, k.key, v.id))
            else:
                g_.edge(root_id, v.id, k.command)
                state_transition_table.append("{} {} {}".format(root_id, k.key, v.id))


# 用于生成区分状态转移的行为字符串
# @param event_ 一个系统调用，将系统调用和参数分割成不同字段的列表
# @return 返回一个引起状态转移的行为操作
def get_trigger(event_: list) -> str:
    # if event_[3] in ['openat', 'socket', 'unlinkat']:
    #     return '{} {}'.format(event_[3], event_[4])
    # if event_[3] in ['read', 'write', 'close', 'connect']:
    #     return '{} {}'.format(event_[3], event_[5])
    # if event_[3] == 'mkdirat':
    #     return '{} {}'.format(event_[3], event_[6])
    # return event_[3]
    return event_[3] + ' ' + event_[4]


# 用于作为边的标识，用于在图中标识状态转移的条件/操作
# @param event_ 一个系统调用及其参数，将系统调用和参数分割成不同字段的列表
# @return 返回该系统调用在图中的标识
def get_label(event_: list) -> str:
    if event_[3] == 'openat':
        return '{} {} {}:({})'.format(event_[3], event_[4], event_[6], event_[5])
    if event_[3] in ['read', 'write', 'close', 'connect']:
        return '{} {}'.format(event_[3], event_[5])
    if event_[3] == 'socket':
        return '{} {}'.format(event_[3], event_[4])
    if event_[3] in ['renameat', 'renameat2']:
        return '{} {} {}'.format(event_[3], event_[6], event_[7])
    if event_[3] == 'mkdirat':
        return '{} {}'.format(event_[3], event_[6])
    if event_[3] == 'unlinkat':
        return '{} {} {}'.format(event_[3], event_[4], event_[6])
    return event_[3]


if __name__ == '__main__':
    syscall_lists = list()
    go_backs = list()
    # for syscall_list in get_syscall_lists('fetch_log.txt'):
    for syscall_list in get_log_list('logs'):
        s = syscall_list[:-1]
        g = find_loop_of_branch(s)
        syscall_lists.append(s)
        go_backs.append(g)
    show_tree(get_tree(syscall_lists, go_backs))
    print(state_transition_table)
    #
    # events = get_log_list()
    # trans_table = {}
    # sm = pydot.Dot()
    #
    # start_state_ = 's0'
    # state_index_ = 1
    #
    # for seq in events:
    #     state_ = start_state_
    #
    #     for event in seq[:-1]:
    #         trigger = get_trigger(event)
    #
    #         if (state_, trigger) not in trans_table:
    #             next_state_ = 's{}'.format(state_index_)
    #             state_index_ += 1
    #             trans_table[(state_, trigger)] = next_state_
    #
    #             edge_ = pydot.Edge(state_, next_state_, label=get_label(event))
    #             sm.add_edge(edge_)
    #
    #         state_ = trans_table[(state_, trigger)]
    #
    #     # 添加最终状态
    #     end_state_ = seq[-1]
    #     edge_ = pydot.Edge(state_, end_state_, label='end')
    #     sm.add_edge(edge_)
    #
    # sm.write('state-machine.png', format='png', prog='dot', encoding='utf-8')
