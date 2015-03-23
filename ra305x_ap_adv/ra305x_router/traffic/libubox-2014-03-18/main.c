#include <stdio.h>

#include "libubox/blobmsg.h"
#include "libubox/blobmsg_json.h"

static const char *indent_str = "\t\t\t\t\t\t\t\t\t\t\t\t\t";

#define indent_printf(indent, ...) do { \
	if (indent > 0) \
		fwrite(indent_str, indent, 1, stderr); \
	fprintf(stderr, __VA_ARGS__); \
} while(0)

static void dump_attr_data(void *data, int len, int type, int indent, int next_indent);

static void
dump_table(struct blob_attr *head, int len, int indent, bool array)
{
	struct blob_attr *attr;
	struct blobmsg_hdr *hdr;

	indent_printf(indent, "{\n");
	__blob_for_each_attr(attr, head, len) {
		hdr = blob_data(attr);
		if (!array)
			indent_printf(indent + 1, "%s : ", hdr->name);
		dump_attr_data(blobmsg_data(attr), blobmsg_data_len(attr), blob_id(attr), 0, indent + 1);
	}
	indent_printf(indent, "}\n");
}

static void dump_attr_data(void *data, int len, int type, int indent, int next_indent)
{
	switch(type) {
	case BLOBMSG_TYPE_STRING:
		indent_printf(indent, "%s\n", (char *) data);
		break;
	case BLOBMSG_TYPE_INT8:
		indent_printf(indent, "%d\n", *(uint8_t *)data);
		break;
	case BLOBMSG_TYPE_INT16:
		indent_printf(indent, "%d\n", *(uint16_t *)data);
		break;
	case BLOBMSG_TYPE_INT32:
		indent_printf(indent, "%d\n", *(uint32_t *)data);
		break;
	case BLOBMSG_TYPE_INT64:
		indent_printf(indent, "%ld\n", *(uint64_t *)data);
		break;
	case BLOBMSG_TYPE_TABLE:
	case BLOBMSG_TYPE_ARRAY:
		if (!indent)
			indent_printf(indent, "\n");
		dump_table(data, len, next_indent, type == BLOBMSG_TYPE_ARRAY);
		break;
	}
}

enum {
	FOO_MESSAGE,
	FOO_LIST,
	FOO_TESTDATA,
	MAT_HW,
	MAT_IP,
	MAT_LIST,
	MAT_TABLE,
};

static const struct blobmsg_policy pol[] = {
	[FOO_MESSAGE] = {
		.name = "message",
		.type = BLOBMSG_TYPE_STRING,
	},
	[FOO_LIST] = {
		.name = "list",
		.type = BLOBMSG_TYPE_ARRAY,
	},
	[FOO_TESTDATA] = {
		.name = "testdata",
		.type = BLOBMSG_TYPE_TABLE,
	},
	[MAT_HW] = { .name = "hw", .type = BLOBMSG_TYPE_STRING },
	[MAT_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[MAT_LIST] = { .name = "mat", .type = BLOBMSG_TYPE_ARRAY },
	[MAT_TABLE] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif


static void dump_mat_data(struct blob_attr *head, int len){
	struct blob_attr *tb[ARRAY_SIZE(pol)];

	if (blobmsg_parse(pol, ARRAY_SIZE(pol), tb, head, len) != 0) {
		fprintf(stderr, "Parse failed\n");
		return;
	}
	if (tb[MAT_HW] && tb[MAT_IP])
		printf("hw:%s ip:%s\n", (char *) blobmsg_data(tb[MAT_HW]), (char *) blobmsg_data(tb[MAT_IP]));
}

static void dump_message(struct blob_buf *buf)
{
	struct blob_attr *tb[ARRAY_SIZE(pol)];

	if (blobmsg_parse(pol, ARRAY_SIZE(pol), tb, blob_data(buf->head), blob_len(buf->head)) != 0) {
		fprintf(stderr, "Parse failed\n");
		return;
	}
	if (tb[FOO_MESSAGE])
		fprintf(stderr, "Message: %s\n", (char *) blobmsg_data(tb[FOO_MESSAGE]));

	if (tb[FOO_LIST]) {
		fprintf(stderr, "List: ");
		dump_table(blobmsg_data(tb[FOO_LIST]), blobmsg_data_len(tb[FOO_LIST]), 0, true);
	}
	if (tb[FOO_TESTDATA]) {
		fprintf(stderr, "Testdata: ");
		dump_table(blobmsg_data(tb[FOO_TESTDATA]), blobmsg_data_len(tb[FOO_TESTDATA]), 0, false);
	}


	if (tb[MAT_LIST]){
		fprintf(stderr, "MAT_LIST: ");
//dump_table(struct blob_attr *head, int len, int indent, bool array)
		struct blob_attr *attr;
		struct blobmsg_hdr *hdr;

struct blob_attr *head = blobmsg_data(tb[MAT_LIST]);
int len = blobmsg_data_len(tb[MAT_LIST]);

		__blob_for_each_attr(attr, head, len) {
			hdr = blob_data(attr);
			printf( "%s : ", hdr->name);
			dump_mat_data(blobmsg_data(attr), blobmsg_data_len(attr));
		}



	}


}

static void
fill_message(struct blob_buf *buf)
{
	void *tbl, *tbl1;
	int i;

	blobmsg_add_string(buf, "message", "Hello, world!");

	tbl = blobmsg_open_table(buf, "testdata");
	blobmsg_add_u32(buf, "hello", 1);
	blobmsg_add_string(buf, "world", "2");
	blobmsg_close_table(buf, tbl);

	tbl = blobmsg_open_array(buf, "list");
	blobmsg_add_u32(buf, NULL, 0);
	blobmsg_add_u32(buf, NULL, 1);
	blobmsg_add_u32(buf, NULL, 2);
	blobmsg_close_table(buf, tbl);

	struct {
		char hw[64];
		char ip[32];
	} mat[] = {
		{"8C:BE:BE:41:BB:01", "192.168.31.201"},
		{"8C:BE:BE:41:BB:02", "192.168.31.202"},
		{"8C:BE:BE:41:BB:03", "192.168.31.203"},
	};

	tbl = blobmsg_open_array(buf, "mat");
	for (i = 0; i < 3; i++){
		tbl1 = blobmsg_open_table(buf, "data");
		blobmsg_add_string(buf, "hw", mat[i].hw);
		blobmsg_add_string(buf, "ip", mat[i].ip);
		blobmsg_close_table(buf, tbl1);
	}
	blobmsg_close_array(buf, tbl);


}

int main(int argc, char **argv)
{
	static struct blob_buf buf;

	blobmsg_buf_init(&buf);
	fill_message(&buf);
	dump_message(&buf);
	//fprintf(stderr, "json: %s\n", blobmsg_format_json(buf.head, false));

	char *str;

	str = blobmsg_format_json(buf.head, true);
	fprintf(stderr, "json: %s\n", str);
	free(str);

	if (buf.buf)
		free(buf.buf);

	return 0;
}
