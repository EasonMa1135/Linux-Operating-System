#include "fs.h"
#include "buf.h"
#include "defs.h"
#include "slub.h"
#include "task_manager.h"
#include "virtio.h"
#include "vm.h"
#include "mm.h"

// --------------------------------------------------
// ----------- read and write interface -------------

void disk_op(int blockno, uint8_t *data, bool write) {
    struct buf b;
    b.disk = 0;
    b.blockno = blockno;
    b.data = (uint8_t *)PHYSICAL_ADDR(data);
    virtio_disk_rw((struct buf *)(PHYSICAL_ADDR(&b)), write);
}

#define disk_read(blockno, data) disk_op((blockno), (data), 0)
#define disk_write(blockno, data) disk_op((blockno), (data), 1)

// -------------------------------------------------
// 全局变量
struct sfs_fs SFS;
bool init = 0;//保存是否初始化过
void strcpy(char *a, const char *b) {
  while (*b) {
    *a++ = *b++;
  }
  *a = '\0';
}
int strlen(const char *a){
    int len = 0;
    while(a[len]) len++;
    return len;
}
#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#define max(X, Y)  ((X) < (Y) ? (Y) : (X))
// ------------------ your code --------------------

int sfs_init(){//应该直接读取块中的内容比较好
    disk_read(0,(&SFS.super));//读取内容
    SFS.freemap = (struct bitmap *) kmalloc(sizeof(struct bitmap));
    if(SFS.freemap == NULL)
        return -1;
    disk_read(2, SFS.freemap->freemap);//读取freemap
    SFS.super_dirty = 0; //刚开始并没有修改过超级块或者freemap
    memset(SFS.block_list, NULL, sizeof(SFS.block_list));
    init = 1;
    return 0;
}

int hash(int blockno) {
    return blockno % HASH_TABLE_SIZE;
}
void insert_into_hash(struct sfs_memory_block *block) {
    int idx = hash(block->blockno);
    list_del(&block);
    list_add(&block, &SFS);
}

void delete_from_hash(struct sfs_memory_block *block) {
    int idx = hash(block->blockno);
    list_del(&block);
}

//获取一个block
void* get_memory_block(uint32_t blockno, bool ifpin)
{
    //先在内存池中查找，如果有的话优先返回内容
    int hashid = hash(blockno);
    struct ListNode* node = NULL;
    for(node = SFS.block_list[hashid]; node != NULL; node = node->next)
        if(blockno == node->data->blockno)
            break;
    //如果找到就直接返回
    if(node != NULL){
        node->data->pin_count += ifpin;
        return node->data->block;
    }
    //初始化新块
    struct ListNode* newnode = kmalloc(sizeof(struct ListNode));
    newnode->data = kmalloc(sizeof(struct sfs_memory_block));
    struct sfs_memory_block* data = newnode->data;
    data->block = kmalloc(4096);
    data->blockno = blockno;
    data->dirty = 0;
    data->pin_count = ifpin;
    disk_read(blockno, data->block);
    //没有的话需要插入这个块
    if(SFS.block_list[hashid] == NULL){//第一个块为空就直接替换
        SFS.block_list[hashid] = newnode;
        newnode->next = NULL;
        newnode->prev = NULL;
    }
    else{
        struct ListNode* Second = SFS.block_list[hashid]->next;
        SFS.block_list[hashid]->next = newnode;
        newnode->prev = SFS.block_list[hashid];
        newnode->next = Second;
        if(Second != NULL)
            Second->prev = newnode;
    }
    return data->block;
}
//解锁一个块
void free_memory_block(uint32_t blockno)
{
    int hashid = hash(blockno);
    struct ListNode* node = NULL;
    for(node = SFS.block_list[hashid]; node != NULL; node = node->next)
        if(blockno == node->data->blockno)
            break;
    //如果找到就直接返回
    if(node != NULL){
        node->data->pin_count--;
        return;
    }
}
inline struct sfs_memory_block *get_inode(int inum) {
    return get_memory_block(inum, 1);
}

inline void free_inode(struct sfs_memory_block *inode) {
    free_memory_block(inode);
}

int balloc() {
    uint8_t *freemap = SFS.freemap;
    for (uint8_t i = 0; i < BLOCK_SIZE / sizeof(uint8_t); i++) {
        for (int j = 0; j < sizeof(uint8_t); j++) {
            if ((freemap[i] >> j) == 0) {
                freemap[i] |= (1 << j);
                int index = i * sizeof(uint8_t) + j;
                // clear the block
                struct sfs_memory_block *block = get_memory_block(index, 0);
                memset(block->block, 0, BLOCK_SIZE);
                block->dirty = 1;
                SFS.super.unused_blocks--;
                free_memory_block(block);
                return i;
            }
        }
    }
    return 0;
}

//设置dirty block
void set_dirty_block(uint32_t blockno){
    int hashid = hash(blockno);
    struct ListNode* node = NULL;
    for(node = SFS.block_list[hashid]; node != NULL; node = node->next)
        if(blockno == node->data->blockno)
            break;
    //如果找到就直接返回
    if(node != NULL){
        node->data->dirty = 1;
        return;
    }
}
//尝试写回某个块
void write_back_block(uint32_t blockno)
{
    int hashid = hash(blockno);
    struct ListNode* node = NULL;
    for(node = SFS.block_list[hashid]; node != NULL; node = node->next)
        if(blockno == node->data->blockno)
            break;
    //如果找不到就直接返回
    if(node == NULL)
        return;
    if(node->data->dirty)//脏块写回
        disk_write(blockno, node->data->block);
    if(node->data->pin_count == 0){//如果没有指针引用就可以释放
        //释放空间
        kfree(node->data->block);
        kfree(node->data);
        struct ListNode* nextnode = node->next;
        if(node == SFS.block_list[hashid]){//删除链表头节点
            SFS.block_list[hashid] = nextnode;
            if(nextnode != NULL)
                nextnode->prev = NULL;
        }
        else{
            struct ListNode* prevnode = node->prev;//prev一定存在
            prevnode->next = nextnode;
            if(nextnode != NULL)
                nextnode->prev = prevnode;
        }
        kfree(node);
    }
}
//将一个inode的所有数据块写回
void write_back_inode(struct sfs_inode * nownode, bool Type)
{
    uint32_t sizePerBlock = (Type == SFS_DIRECTORY ? SFS_NENTRY * sizeof(struct sfs_entry) : 4096); 
    for(int i = 0; i < SFS_NDIRECT && i < (nownode->size + sizePerBlock - 1) / sizePerBlock; i++)
        write_back_block(nownode->direct[i]);
    if((nownode->size >> 12) > SFS_NDIRECT){//文件过大需要考虑间接索引是否存在
        uint32_t* indirect = get_memory_block(nownode->indirect, 1);
        for(int i = SFS_NDIRECT; i < (nownode->size + sizePerBlock - 1) / sizePerBlock; i++)
            write_back_block(indirect[i - SFS_NDIRECT]);
        free_memory_block(nownode->indirect);
        write_back_block(nownode->indirect);
    }
}

//找到一个新的空Block的编号
int NewBlock()
{
    SFS.super.unused_blocks--;
    SFS.super_dirty = 1;
    int i = 0, j = 0;
    for(;i <= 4096 && SFS.freemap->freemap[i] == 0xFF; i++);//找到第一个可能空的块
    for(;(SFS.freemap->freemap[i] >> j) & 1; j++);//找到空块里的第一个空点
    SFS.freemap->freemap[i] |= 1 << j;//初始化
    return (i << 3) + j;
}
void release_resources(uint32_t inode_number)
{
    free_memory_block(inode_number);
    write_back_block(inode_number);
}

struct sfs_inode* get_inode_from_path(struct sfs_inode* path, uint32_t inode_number)
{
    struct sfs_entry* entries = get_memory_block(path->direct[0], 1);
    uint32_t next_inode_number = entries[1].ino;
    free_memory_block(path->direct[0]);
    return get_memory_block(next_inode_number, 1);
}

uint32_t get_now_inode(struct sfs_inode* inode)
{
    struct sfs_entry* entries = get_memory_block(inode->direct[0], 1);
    uint32_t now_inode = entries[1].ino;
    free_memory_block(inode->direct[0]);
    return now_inode;
}

/*
调用 sfs_init 函数进行初始化。
检查路径是否是一个合法路径
循环解析路径，每次循环处理路径中的一个部分（由斜杠分隔）
遍历路径，检查当前节点是否是文件
如果是文件，返回 -1
如果当前节点是目录，寻找匹配项
找到匹配项，更新当前节点为找到的节点，继续处理下一个路径部分
检查进程的文件打开表，找到空闲的位置存放新文件
*/
int sfs_open(const char *path, uint32_t flags) {
    if (!init)
        initialize_sfs();
    if (path[0] != '/')
        return -1;
    struct sfs_inode *currentNode = (struct sfs_inode*)get_memory_block(1, 1);
    struct sfs_inode *previousNode = NULL, *nextNode = NULL;
    int pathIndex = 1, nextPathIndex = 1;
    uint32_t currentInode = 1, previousInode = 1, nextInode = 1;
    while (path[nextPathIndex] != '\0') 
    {
        nextPathIndex = pathIndex;
        while (path[nextPathIndex] && path[nextPathIndex] != '/')
            nextPathIndex++;
        if (currentNode->type == SFS_FILE)
            return -1;
        if (currentNode->type == SFS_DIRECTORY) {
            bool found = 0;
            int totalEntries = currentNode->size / sizeof(struct sfs_entry);
            for (int i = 0; i < currentNode->blocks && i < SFS_NDIRECT; i++) 
            {
                struct sfs_entry *entries = get_memory_block(currentNode->direct[i], 1);
                for (int j = 0; j < SFS_NENTRY && i * SFS_NENTRY + j < totalEntries; j++) 
                {
                    bool match = ((nextPathIndex - pathIndex) == strlen(entries[j].filename));
                    for (int k = 0; match && k < nextPathIndex - pathIndex; k++) 
                    {
                        if (entries[j].filename[k] != path[pathIndex + k]) 
                        {
                            match = 0;
                            break;
                        }
                    }
                    if (match) 
                    {
                        nextInode = entries[j].ino;
                        free_memory_block(currentNode->direct[i]);
                        nextNode = (struct sfs_inode*)get_memory_block(entries[j].ino, 1);
                        found = 1;
                        break;
                    }
                }
                if (found)
                    break;
                free_memory_block(currentNode->direct[i]);
            }
            if (!found) 
            { 
                int newBlockNumber = NewBlock();
                struct sfs_inode *newInode = (struct sfs_inode*)get_memory_block(newBlockNumber, 1);
                newInode->size = path[nextPathIndex] ? sizeof(struct sfs_entry) * 2 : 0;
                newInode->type = path[nextPathIndex] ? SFS_DIRECTORY : SFS_FILE;
                newInode->links = newInode->blocks = 1;
                newInode->direct[0] = NewBlock();
                newInode->indirect = 0;
                set_dirty_block(newBlockNumber);
            struct sfs_entry directoryEntries[2];
            if (newInode->type == SFS_DIRECTORY) {
                directoryEntries[0].ino = newBlockNumber;
                strcpy(directoryEntries[0].filename, ".");
                directoryEntries[1].ino = currentInode;
                strcpy(directoryEntries[1].filename, "..");
                disk_write_operation(newInode->direct[0], &directoryEntries);
            }
            struct sfs_entry newDirEntry;
            for (int k = 0; k < nextPathIndex - pathIndex; k++)
                newDirEntry.filename[k] = path[pathIndex + k];
            newDirEntry.filename[nextPathIndex - pathIndex] = '\0';
            newDirEntry.ino = newBlockNumber;
            if (currentNode->size != currentNode->blocks * sizeof(struct sfs_entry) * SFS_NENTRY) 
            {
                struct sfs_entry *lastBlockEntries = get_memory_block(currentNode->direct[currentNode->blocks - 1], 1);
                lastBlockEntries[totalEntries % SFS_NENTRY] = newDirEntry;
                set_dirty_block(currentNode->direct[currentNode->blocks - 1]);
                free_memory_block(currentNode->direct[currentNode->blocks - 1]);
            } 
            else 
            {
                currentNode->direct[currentNode->blocks] = NewBlock();
                disk_write_operation(currentNode->direct[currentNode->blocks], &newDirEntry);
                currentNode->blocks++;
            }
            currentNode->size += sizeof(struct sfs_entry);
            set_dirty_block(currentInode);
            nextNode = newInode;
            nextInode = newBlockNumber;
        }
    }
    if (!(previousInode == currentInode && previousInode == 1))
        free_memory_block(previousInode);
    previousNode = currentNode;
    previousInode = currentInode;
    currentNode = nextNode;
    currentInode = nextInode;
    pathIndex = nextPathIndex + 1;
}
if (currentNode->type == SFS_DIRECTORY)
    return -1;
for(int i = 0; i < 16; i++)
    if(current->fs.fds[i] == NULL)
    {
        current->fs.fds[i] = kmalloc(sizeof(struct file));
        current->fs.fds[i]->flags = flags;
        current->fs.fds[i]->inode = currentNode;
        current->fs.fds[i]->off = 0;
        current->fs.fds[i]->path = previousNode;
        current->fs.fds[i]->ino = currentInode;
        current->fs.fds[i]->fa_ino = previousInode;
        return i;
    }
}
/*
从文件结构体中获取指向文件 inode 的指针
将文件的 inode 写回磁盘
释放文件 inode 占用的内存。
将文件的数据块写回磁盘
获取路径上的 inode和其 inode号
循环遍历路径上的所有节点，直到到达根目录
对于每个节点，获取其目录项，释放并写回其数据块和 inode
*/
int sfs_close(int fd)
{
    struct file* file_ptr = current->fs.fds[fd];
    if (file_ptr == NULL) 
        return -1;
    struct sfs_inode *now_node = file_ptr->inode;
    write_back_inode(now_node, SFS_FILE);
    release_resources(file_ptr->ino);
    uint32_t now_inode = file_ptr->fa_ino;
    while (now_inode != 1) 
    {  
        now_node = get_inode_from_path(file_ptr->path, now_inode);
        if (!now_node) 
            break;
        write_back_inode(now_node, SFS_DIRECTORY);
        if (now_inode == file_ptr->fa_ino)
            release_resources(now_inode);
        now_inode = get_now_inode(now_node);
    }
    write_back_inode(now_node, SFS_DIRECTORY);
    write_back_block(now_inode);
    if(SFS.super_dirty)
    {
        disk_write(0, &SFS.super);
        disk_write(2, SFS.freemap->freemap);
        SFS.super_dirty = 0;
    }
    kfree(current->fs.fds[fd]);
    current->fs.fds[fd] = NULL;
    return 0;
}

int sfs_seek(int fd, int32_t off, int fromwhere){
    struct file * f = current->fs.fds[fd];
    switch (fromwhere)
    {
        case SEEK_SET:
            f->off = off;
            break;
        case SEEK_END:
            f->off = f->inode->size - off;
            break;
        default:
            f->off = f->off + off;
            break;
    }
    if(f->off < 0 || f->off >= f->inode->size)
        return -1;
    else
        return 0;
}

int sfs_read(int fd, char *buf, uint32_t len) 
{
    struct file *file_ptr = current->fs.fds[fd];
    len = min(len, file_ptr->inode->size - file_ptr->off);
    int block_idx = file_ptr->off / 4096;
    int block_offset = file_ptr->off % 4096;
    uint32_t copied_len = 0;
    struct sfs_inode* inode_ptr = file_ptr->inode;
    while (block_idx < SFS_NDIRECT && len > 0) 
    {
        uint32_t to_copy = min(len, 4096 - block_offset);
        char *block_mem = get_memory_block(inode_ptr->direct[block_idx], 1);
        memcpy(&buf[copied_len], block_mem + block_offset, to_copy);
        free_memory_block(inode_ptr->direct[block_idx]);
        copied_len += to_copy;
        len -= to_copy;
        block_idx++;
        block_offset = 0;
    }
    if (len > 0 && inode_ptr->indirect != 0) {
    block_idx -= SFS_NDIRECT;
    uint32_t *indirect_block = get_memory_block(inode_ptr->indirect, 1);
    while (len > 0 && block_idx < SFS_NDIRECT) 
    {
        uint32_t to_copy = min(len, 4096);
        char *block_mem = get_memory_block(indirect_block[block_idx], 1);
        memcpy(&buf[copied_len], block_mem, to_copy);
        free_memory_block(indirect_block[block_idx]);
        copied_len += to_copy;
        len -= to_copy;
        block_idx++;
    }
    free_memory_block(inode_ptr->indirect);
    }
    file_ptr->off += copied_len;
    return copied_len;
}

int sfs_write(int fd, char *buf, uint32_t len) {
    struct file *f_ptr = current->fs.fds[fd];
    int blk_idx = f_ptr->off / 4096;
    int offset_in_blk = f_ptr->off % 4096;
    uint32_t buf_offset = 0;
    if (len > f_ptr->inode->size - f_ptr->off) 
    {
        f_ptr->inode->size = f_ptr->off + len;
        set_dirty_block(f_ptr->ino);
    }
    while (blk_idx < SFS_NDIRECT && len > 0) 
    {
        if (blk_idx >= f_ptr->inode->blocks) 
        {
            f_ptr->inode->direct[blk_idx] = NewBlock();
            f_ptr->inode->blocks++;
        }
        uint32_t blk_len = min(len, 4096 - offset_in_blk);
        char *blk = get_memory_block(f_ptr->inode->direct[blk_idx], 1);
        memcpy(blk + offset_in_blk, buf + buf_offset, blk_len);
        set_dirty_block(f_ptr->inode->direct[blk_idx]);
        free_memory_block(f_ptr->inode->direct[blk_idx]);
        buf_offset += blk_len;
        len -= blk_len;
        blk_idx++;
        offset_in_blk = 0;
    }
    if (len > 0) 
    {
        if (f_ptr->inode->indirect == 0) 
        {
            f_ptr->inode->indirect = NewBlock();
            f_ptr->inode->blocks++;
        }
        uint32_t *indirect = get_memory_block(f_ptr->inode->indirect, 1);
        blk_idx -= SFS_NDIRECT;
        while (len > 0) 
        {
            if (blk_idx >= f_ptr->inode->blocks - SFS_NDIRECT) 
            {
                indirect[blk_idx] = NewBlock();
                f_ptr->inode->blocks++;
            }
            uint32_t blk_len = min(len, 4096);
            char *blk = get_memory_block(indirect[blk_idx], 1);
            memcpy(blk, buf + buf_offset, blk_len);
            set_dirty_block(indirect[blk_idx]);
            free_memory_block(indirect[blk_idx]);
            buf_offset += blk_len;
            len -= blk_len;
            blk_idx++;
        }
        free_memory_block(f_ptr->inode->indirect);
    }
    f_ptr->off += buf_offset;
    return buf_offset;
}

int sfs_get_files(const char* path, char* files[]){
    if (!init)
        initialize_sfs();
    if (path[0] != '/')
        return -1;
    struct sfs_inode *currentNode = (struct sfs_inode*)get_memory_block(1, 1);
    struct sfs_inode *previousNode = NULL, *nextNode = NULL;
    int pathIndex = 1, nextPathIndex = 1;
    uint32_t currentInode = 1, previousInode = 1, nextInode = 1;
    while (path[nextPathIndex] != '\0') 
    {
        nextPathIndex = pathIndex;
        while (path[nextPathIndex] && path[nextPathIndex] != '/')
            nextPathIndex++;
        if (currentNode->type == SFS_FILE)
            return -1;
        if (currentNode->type == SFS_DIRECTORY) {
            bool found = 0;
            int totalEntries = currentNode->size / sizeof(struct sfs_entry);
            for (int i = 0; i < currentNode->blocks && i < SFS_NDIRECT; i++) 
            {
                struct sfs_entry *entries = get_memory_block(currentNode->direct[i], 1);
                for (int j = 0; j < SFS_NENTRY && i * SFS_NENTRY + j < totalEntries; j++) 
                {
                    bool match = ((nextPathIndex - pathIndex) == strlen(entries[j].filename));
                    for (int k = 0; match && k < nextPathIndex - pathIndex; k++) 
                    {
                        if (entries[j].filename[k] != path[pathIndex + k]) 
                        {
                            match = 0;
                            break;
                        }
                    }
                    if (match) 
                    {
                        nextInode = entries[j].ino;
                        free_memory_block(currentNode->direct[i]);
                        nextNode = (struct sfs_inode*)get_memory_block(entries[j].ino, 1);
                        found = 1;
                        break;
                    }
                }
                if (found)
                    break;
                free_memory_block(currentNode->direct[i]);
            }
            if(!found)
                return -1;
        }
        if(!(previousInode == currentInode && previousInode == 1))
            free_memory_block(previousInode);
        previousNode = currentNode;
        previousInode = currentInode;
        currentNode = nextNode;
        currentInode = nextInode;
        pathIndex = nextPathIndex + 1;
    }
    if(currentNode->type == SFS_FILE)
        return 0;
    uint32_t sizePerBlock = SFS_NENTRY * sizeof(struct sfs_entry), count = 0;
    for(int i = 0; i < SFS_NDIRECT && i < (currentNode->size + sizePerBlock - 1) / sizePerBlock; i++){
        struct sfs_entry* entrys = get_memory_block(currentNode->direct[i], 1);
        for(int j = 0; j < SFS_NENTRY && i * sizePerBlock + j * sizeof(struct sfs_entry) < currentNode->size; j++)
            strcpy(files[count++], entrys[j].filename);
        free_memory_block(currentNode->direct[i]);
    }
    if((currentNode->size >> 12) > SFS_NDIRECT)
    {
        uint32_t* indirect = get_memory_block(currentNode->indirect, 1);
        for(int i = SFS_NDIRECT; i < (currentNode->size + sizePerBlock - 1) / sizePerBlock; i++){
            struct sfs_entry* entrys = get_memory_block(indirect[i - SFS_NDIRECT], 1);
            for(int j = 0; j < SFS_NENTRY && i * sizePerBlock + j * sizeof(struct sfs_entry) < currentNode->size; j++)
                strcpy(files[count++], entrys[j].filename);
            free_memory_block(indirect[i - SFS_NDIRECT]);
        }
        free_memory_block(currentNode->indirect);
    }
    return count;
}