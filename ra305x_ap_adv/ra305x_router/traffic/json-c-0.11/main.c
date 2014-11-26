#include <stdio.h>
#include <string.h>
#include <json.h>

int main(int argc,char **argv) {

	json_object *json=json_object_new_object();
	json_object_object_add(json,
			"1",json_object_new_string("hello"));
	json_object_object_add(json,
			"2",json_object_new_string("world!"));
	const char *str=json_object_to_json_string(json);
	printf("%s\n",str);
	json_object_put(json);
	return 0;
}


