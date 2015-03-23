#include <stdio.h>
#include <string.h>
#include <json/json.h>

int main(int argc,char **argv) {
	const char *str;
	json_object *payload = json_object_new_object();
	json_object_object_add(payload,
			"mac",json_object_new_string("00:23:54:7c:54:66"));
	json_object_object_add(payload,
			"ip",json_object_new_string("192.168.31.1"));
	json_object_object_add(payload,
			"eventID",json_object_new_int(1));
	
	json_object *json=json_object_new_object();
	json_object_object_add(json,
			"mac",json_object_new_string("00:23:54:7c:54:66"));
	json_object_object_add(json,
			"ip",json_object_new_string("192.168.31.1"));
	json_object_object_add(json,
			"eventID",json_object_new_int(1));

	str=json_object_to_json_string(payload);
	json_object_object_add(json,
			"payload",json_object_new_string(str));
	json_object_put(payload);
	//str=json_object_to_json_string(json);
	//printf("%s\n",str);


	json_object *j = json_object_new_array();
	json_object_array_add(j, json);
	json_object_array_add(j, json);
	json_object_array_add(j, json);

	str=json_object_to_json_string(j);
	printf("%s\n",str);
	json_object_put(j);
	json_object_put(j);
	return 0;
}


