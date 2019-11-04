#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define SIZE 4096

long int mem;
char file_name[256];

typedef struct file_node {
	char name[256];
	char type;
	char *contents;
	struct file_node *parent;
	struct file_node *child;
	struct file_node *next;
	struct stat *st;
} Node;

Node *root;

int validate_path(const char* path);
Node* get_file_node(const char* path);

static int create_callback(const char *path, mode_t mode,struct fuse_file_info *fi) {

	long int node_size = sizeof(Node) + sizeof(stat);
	if (mem < node_size)
		return -ENOSPC;

	mem = mem - node_size;

	Node* node = get_file_node(path);
	Node* temp = (Node *) malloc(sizeof(Node));

	temp->st = (struct stat *) malloc(sizeof(struct stat));

	if (temp == NULL)
		return -ENOSPC;

	strcpy(temp->name, file_name);
	temp->type = 'f';
	temp->parent = node;
	temp->next = NULL;
	temp->child = NULL;
	temp->st->st_uid = getuid();
	temp->st->st_mode = S_IFREG | mode;
	temp->st->st_gid = getgid();
	temp->st->st_nlink = 1;
	temp->st->st_atime = time(NULL);
	temp->st->st_mtime = time(NULL);
	temp->st->st_ctime = time(NULL);
	temp->st->st_size = 0;
	temp->contents = NULL;

	Node* child = node->child;

	if (child == NULL)
		node->child = temp;

	else {
		while (child->next != NULL) {
			child = child->next;
		}
		child->next = temp;
	}

	return 0;
}

static int write_callback(const char *path, const char *buf, size_t size,off_t offset, struct fuse_file_info *fi) {	

	Node* node = get_file_node(path);

	if (node->type == 'd')
		return -EISDIR;

	size_t file_size = node->st->st_size;

	if (offset + size -file_size > mem)
		return -ENOSPC;

	if (size > 0) {
		if (file_size == 0) {

			offset = 0;
			node->contents = (char *) malloc((sizeof(char) * size));

		} else {

			if (offset > file_size)
				offset = file_size;

			if(offset + size > file_size) {
				char* new_contents = (char *) realloc(node->contents,(sizeof(char) * (offset + size)));

				if (new_contents == NULL)
					return -ENOSPC;
				else
					node->contents = new_contents;

				mem = mem - (offset+size-file_size);
			}
		}

		memcpy(node->contents + offset, buf, size);

		node->st->st_size = offset + size;
		node->st->st_ctime = time(NULL);
		node->st->st_mtime = time(NULL);		
	}

	return size;
}

static int read_callback(const char *path, char *buf, size_t size, off_t offset,struct fuse_file_info *fi) {

	Node* node = get_file_node(path);
	size_t file_size = node->st->st_size;

	if (node->type == 'd')
		return -EISDIR;

	if(offset < file_size) {

		if(offset + size > file_size)
			size = file_size - offset;
		memcpy(buf, node->contents + offset, size);
		node->st->st_atime = time(NULL);

	} else
		size = 0;

	return size;
}

static int open_callback(const char* path, struct fuse_file_info* fi) {

	int res = validate_path(path);

	if (res != 0)
		return -ENOENT;;

	return 0;
}

static int mkdir_callback(const char* path, mode_t mode) {

	long int node_size = sizeof(Node) + sizeof(stat);

	if (mem < node_size)
		return -ENOSPC;

	mem = mem - node_size;

	Node* node = get_file_node(path);
	Node* temp = (Node *) malloc(sizeof(Node));

	temp->st = (struct stat *) malloc(sizeof(struct stat));

	if (temp == NULL)
		return -ENOSPC;

	strcpy(temp->name, file_name);
	temp->type = 'd';
	temp->parent = node;
	temp->next = NULL;
	temp->child = NULL;
	temp->st->st_uid = getuid();
	temp->st->st_mode = S_IFDIR | 0755;
	temp->st->st_gid = getgid();
	temp->st->st_nlink = 2;
	temp->st->st_atime = time(NULL);
	temp->st->st_mtime = time(NULL);
	temp->st->st_ctime = time(NULL);
	temp->st->st_size = SIZE;

	
	Node* child = node->child;

	if (child == NULL)
		node->child = temp;

	else {
		while (child->next != NULL) {
			child = child->next;
		}
		child->next = temp;
	}

	node->st->st_nlink += 1;

	return 0;
}

static int opendir_callback(const char* path, struct fuse_file_info* fi) {
	return 0;
}

static int readdir_callback(const char* path, void* buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info* fi) {

	(void) offset;
	(void) fi;

	Node* node;
	Node* child = NULL;

	int res = validate_path(path);

	if ((res == 0) || (res == 1)) {

		node = get_file_node(path);

		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);

		child = node->child;

		while (child != NULL) {
			filler(buf, child->name, NULL, 0);
			child = child->next;
		}

		node->st->st_atime = time(NULL);
	} else
		return -ENOENT;

	return 0;
}

static int rmdir_callback(const char *path) {

	Node* node;
	Node* parent;
	Node* child;

	int res = validate_path(path);

	if (res == 0) {

		node = get_file_node(path);

		if (node->child != NULL)
			return -ENOTEMPTY;

		else {

			parent = node->parent;

			if (parent->child == node)
				parent->child = node->next;

			else {
				child = parent->child;

				while(child->next != node)
					child = child->next;

				child->next = node->next;
			}

			free(node->st);
			free(node);
			mem = mem + sizeof(Node) + sizeof(struct stat);
			parent->st->st_nlink -= 1;
		}
	} else
		return -ENOENT;

	return 0;
}

static int unlink_callback(const char *path) {

	int res = validate_path(path);

	if (res != 0)
		return -ENOENT;

	Node* node = get_file_node(path);
	Node* parent = node->parent;
	Node* child;

	if (parent->child == node)
		parent->child = node->next;

	else {
		child = parent->child;

		while(child->next != node)
			child = child->next;

		child->next = node->next;
	}

	if (node->st->st_size > 0) {

		mem = mem + node->st->st_size;
		free(node->contents);
	}

	free(node->st);
	free(node);

	mem = mem + sizeof(Node) + sizeof(struct stat);

	return 0;
}

static int getattr_callback(const char *path, struct stat *st) {

	int res = validate_path(path);

	if (res == 0) {
		Node* node = get_file_node(path);

		st->st_uid = node->st->st_uid;
		st->st_gid = node->st->st_gid;
		st->st_atime = node->st->st_atime;
		st->st_mtime = node->st->st_mtime;
		st->st_ctime = node->st->st_ctime;
		st->st_nlink = node->st->st_nlink;
		st->st_size = node->st->st_size;
		st->st_mode = node->st->st_mode;

	} 

	else
		return -ENOENT;

	return 0;
}

static int truncate_callback(const char *path, off_t size) {

	int res = validate_path(path);

	if (res != 0)
		return -ENOENT;

	return 0;
}

static int utimens_callback(const char* path, const struct timespec ts[2]) {

	int res = validate_path(path);

	if (res != 0)
		return -ENOENT;

	return 0;
}

int validate_path(const char *path) {

	char dupPath[SIZE];
	strcpy(dupPath, path);

	char* token = strtok(dupPath, "/");

	if (token == NULL && strcmp(path, "/") == 0)
		return 0;

	else {

		int child_flag = 0;
		Node* temp = root;
		Node* child = NULL;

		while (token != NULL) {

			child = temp->child;

			while (child != NULL) {

				if (strcmp(child->name, token) == 0) {

					child_flag = 1;
					break;
				}
				child = child->next;
			}

			token = strtok(NULL, "/");

			if (child_flag == 1) {

				if(token == NULL)
					return 0;
			}

			else {

				if (token)
					return -1;
				else
					return 1;
			}

			temp = child;
			child_flag = 0;
		}
	}
	return -1;
}

Node* get_file_node(const char *path) {

	char dupPath[SIZE];
	strcpy(dupPath, path);

	char* token = strtok(dupPath, "/");

	if (token == NULL && strcmp(path, "/") == 0)
		return root;

	else {

		int child_flag = 0;
		Node* temp = root;
		Node* child = NULL;

		while (token != NULL) {

			child = temp->child;

			while (child != NULL) {

				if (strcmp(child->name, token) == 0) {

					child_flag = 1;
					break;
				}

				child = child->next;
			}

			if (child_flag == 1) {

				strcpy(file_name, token);
				token = strtok(NULL, "/");

				if (token == NULL) {

					if (child == NULL)
						return temp;
					else
						return child;
				}

			} else {

				strcpy(file_name, token);
				return temp;
			}

			temp = child;
			child_flag = 0;
		}
	}
	return NULL;
}

static struct fuse_operations mappings = {
	.create = create_callback,
	.write = write_callback,
	.read = read_callback,
	.open = open_callback,
	.mkdir = mkdir_callback,
	.readdir = readdir_callback,
	.opendir =opendir_callback,
	.rmdir = rmdir_callback,
	.unlink = unlink_callback,
	.getattr = getattr_callback,
	.truncate = truncate_callback,
	.utimens = utimens_callback	
};

void ramdisk_init() {

	root = (Node *) malloc(sizeof(Node));
	root->st = (struct stat *) malloc(sizeof(struct stat));

	root->type = 'd';
	root->parent = NULL;
	strcpy(root->name, "/");
	root->next = NULL;
	root->child = NULL;
	root->st->st_uid = getuid();
	root->st->st_mode = S_IFDIR | 0755;
	root->st->st_gid = getgid();
	root->st->st_nlink = 2;
	root->st->st_atime = time(NULL);
	root->st->st_mtime = time(NULL);
	root->st->st_ctime = time(NULL);
	root->contents = NULL;

	long int root_size = sizeof(Node) + sizeof(stat);

	mem = mem - root_size;
}

int main(int argc, char *argv[]) {

	if (argc != 3) {
		printf("Incorrect usage!\n");
		printf("Correct usage: ./ramdisk <mount_point> <size>\n");

		exit(EXIT_FAILURE);
	}

	mem = atoi(argv[argc - 1]);

	mem = mem * 1024 * 1024;
	ramdisk_init();
	fuse_main(argc - 1, argv, &mappings, NULL);
	return 0;
}