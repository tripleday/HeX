
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"
#include "Server.h"
#include "Client.h"
#include "Utils.h"

//for measurement
#include <cstdint>
#include <chrono>
#include <iostream>
#include <bitset> 
#include <random>
#include <vector>
#include <algorithm>
using std::bitset;  
#include <cmath>

uint64_t timeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
uint64_t timeSinceEpochMicrosec() {
  using namespace std::chrono;
  return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}
//end for measurement


#define ENCLAVE_FILE "CryptoEnclave.signed.so"

/* 	Note 1: Enclave only recognises direct pointer with count*size, where count is the number of elements in the array, and size is the size of each element
		other further pointers of pointers should have fixed max length of array to eliminate ambiguity to Enclave (by using pointer [max_buf]).
	Note 2: In outcall, passing pointer [out] can only be modified/changed in the direct .cpp class declaring the ocall function.
	Note 3: If it is an int pointer pointing to a number-> using size=sizeof(int) to declare the size of the int pointer. That will be a larger range than using size_t in ocall
	Note 4: ensure when using openssl and sgxcrypto, plaintext data should be more lengthy than 4-5 characters; (each content in raw_doc should have lengthy characters)
			otherwise, random noise/padding will be auto added.
	Note 5: convert to int or length needs to total_filecome with pre-define length;otherwise, following random bytes can occur.

	memory leak note: 
	1-declare all temp variable outside forloop
	2-all func should return void, pass pointer to callee; caller should init mem and free pointer
	3-use const as input parameter in funcs if any variable is not changed 
	4-re-view both client/server in outside regarding above leak,
		 (docContent fetch_data = myClient->ReadNextDoc();, 

			//free memory 
			free(fetch_data.content);
			free(fetch_data.id.doc_id);)
	5-struct should use constructor and destructor (later)
	6-should use tool to check mem valgrind --leak-check=yes to test add function to see whether memory usage/leak before and after
	7-run with prerelease mode
	8-re generate new list test, but without using the list inside
 */


Client *myClient; //extern to separate ocall
Server *myServer; //extern to separate ocall

void ocall_print_string(const char *str) {
    printf("%s\n", str);
}

void ocall_retrieve_edbs(void *ins, void *ins_res, size_t in_amt, size_t label_size, size_t cipher_size) {// query index in the untrusted server
	std::vector<std::string> query_result = myServer->retrieve_edbs((label_struct *) ins, in_amt);
	// *res = query_result.size();
	//printf("%ld documents found\n", *res);

	// fill the output array
	for(int i = 0; i < query_result.size(); i++) {
		memcpy(((cipher_struct *) ins_res + i)->content, query_result[i].c_str(), query_result[i].length());
		((cipher_struct *) ins_res + i)->content_length = query_result[i].length();
	}

}

void ocall_retrieve_edb(void *ins, void *ins_res, size_t label_size, size_t cipher_size) {// query index in the untrusted server
	std::string query_result = myServer->retrieve_edb((label_struct *) ins);
    // std::cout << query_result << std::endl;
    memcpy(((cipher_struct *) ins_res)->content, query_result.c_str(), query_result.length());
    ((cipher_struct *) ins_res)->content_length = query_result.length();
}

void ocall_add_edbs(void *outs, void *outs_res, size_t out_amt, size_t label_size, size_t cipher_size) {// query index in the untrusted server
	myServer->add_edbs((label_struct *) outs, (cipher_struct *) outs_res, out_amt);
}


void ocall_transfer_edbs(const void *_t1_u_arr,
									  const void *_t1_v_arr, 
									  int pair_count, int rand_size){

	myServer->ReceiveTransactions(
								(rand_t *)_t1_u_arr,(rand_t *)_t1_v_arr,
								pair_count);

}

void ocall_retrieve_encrypted_doc(const char *del_id, size_t del_id_len, 
                                  unsigned char *encrypted_content, size_t maxLen,
                                  int *length_content, size_t int_size){
								  
	std::string del_id_str(del_id,del_id_len);	
	std::string encrypted_entry = myServer->Retrieve_Encrypted_Doc(del_id_str);
	
    *length_content = (int)encrypted_entry.size();

	//later double check *length_content exceeds maxLen
    memcpy(encrypted_content, (unsigned char*)encrypted_entry.c_str(),encrypted_entry.size());
}

void ocall_del_encrypted_doc(const char *del_id, size_t del_id_len){
	std::string del_id_str(del_id,del_id_len);
	myServer->Del_Encrypted_Doc(del_id_str);
}


void ocall_query_tokens_entries(const void *Q_w_u_arr,
                               const void *Q_w_id_arr,
                               int pair_count, int rand_size){
	
	std::vector<std::string> Res;
	Res = myServer->retrieve_query_results(
								(rand_t *)Q_w_u_arr,(rand_t *)Q_w_id_arr,
								pair_count);
	
	// //give to Client for decryption
	// myClient->DecryptDocCollection(Res);
}


//main func
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}

	/* Setup Protocol*/
	//Client
	myClient= new Client();

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE];
	myClient->getKFValue(KFvalue);
	ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE);

	//Server	
	myServer= new Server();

	printf("Adding doc\n");


    // std::unordered_map<std::string,bitset<32>> CK;
    // bitset<32> b1(0xffff0000);
    // bitset<32> b2(0xffff);
    // bitset<32> b3;
    // CK.insert(std::pair<std::string,bitset<32>>("b1",b1));
    // CK.insert(std::pair<std::string,bitset<32>>("b2",b2));
    // std::cout << CK.size() << std::endl;  
    // CK.insert(std::pair<std::string,bitset<32>>("b3",b3));
    // std::cout << CK.size() << std::endl;  
    // std::vector<std::pair<std::string,bitset<32>>> out;
    // std::sample(CK.begin(), CK.end(), std::back_inserter(out), 2, std::mt19937{std::random_device{}()});
    // std::cout << out.size() << std::endl;  
    
    // for (auto it = CK.begin(); it != CK.end(); ++it) {
    //     std::cout << it->first << " " << it->second << std::endl;
    // }

    // printf("%s \n", b2.to_string().c_str()); 
    // printf("%d \n", b2.to_string().length()); 
    // std::string b2_str = b2.to_string();
    // // std::reverse(b2_str.begin(),b2_str.end());
    // printf("%s \n", b2_str.c_str()); 
    // printf("%d \n", b2_str.length()); 
    // bitset<32> b4(b2_str);
    // std::cout << b4[0] << std::endl;  
    // std::cout << b4[31] << std::endl;  
    // std::cout << b4 << std::endl;  
    // std::cout << b1[0] << std::endl;  
    // std::cout << b1[31] << std::endl;  



	// std::cout << timeSinceEpochMillisec() << std::endl;
    uint64_t t_start = timeSinceEpochMillisec();
	
	/*** Update Protocol with op = add */
	for(int i=1;i <= total_file_no; i++){  //total_file_no
		//client read a document
		// printf("->%d",i);
		
		docContent *fetch_data;
		fetch_data = (docContent *)malloc(sizeof( docContent));
		myClient->ReadNextDoc(fetch_data);

		// //encrypt and send to Server
		// entry *encrypted_entry;
		// encrypted_entry = (entry*)malloc(sizeof(entry));
		
		// encrypted_entry->first.content_length = fetch_data->id.id_length;
		// encrypted_entry->first.content = (char*) malloc(fetch_data->id.id_length);
		// encrypted_entry->second.message_length = fetch_data->content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE;		
		// encrypted_entry->second.message = (char *)malloc(encrypted_entry->second.message_length);


		// myClient->EncryptDoc(fetch_data,encrypted_entry);
		
		// myServer->ReceiveEncDoc(encrypted_entry);
		
		//upload (op,in) to Enclave
		ecall_updateDoc(eid,fetch_data->id.doc_id,fetch_data->id.id_length,
						fetch_data->content,fetch_data->content_length, &ADD, sizeof(ADD));

		//free memory 
		free(fetch_data->content);
		free(fetch_data->id.doc_id);
		free(fetch_data);

		// free(encrypted_entry->first.content);
		// free(encrypted_entry->second.message);
		// free(encrypted_entry);
	}
    uint64_t t_end = timeSinceEpochMillisec();
    std::cout << (t_end-t_start) << " ms" << std::endl;
    

	
// 	//** Update Protocol with op = del (id)
// 	printf("\nDeleting docccccccccccccccccccccccccccc\n");

//     t_start = timeSinceEpochMillisec();
// 	for(int del_index=1; del_index <=del_no; del_index++){
// //		//printf("->%s",delV_i[del_index].doc_id);
// 		docContent *fetch_data;
// 		fetch_data = (docContent *)malloc(sizeof( docContent));
// 		myClient->DelDoc(del_index, fetch_data);
// 		ecall_updateDoc(eid,fetch_data->id.doc_id,fetch_data->id.id_length,
// 						fetch_data->content,fetch_data->content_length, &DEL, sizeof(DEL));
// 		free(fetch_data->content);
// 		free(fetch_data->id.doc_id);
// 		free(fetch_data);
// 	}
//     t_end = timeSinceEpochMillisec();
//     std::cout << (t_end-t_start) << " ms" << std::endl;


    myServer->print_mem();
    ecall_printMem(eid);


    int minValue = 0;
    int maxValue = pow(2,bits)-1;
    int rounds = 1000;

    std::vector<int> randomNumbers;

    for (int i = 0; i < rounds; ++i) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minValue, maxValue);
        int randomNumber = dis(gen);
        randomNumbers.push_back(randomNumber);
    }

    t_start = timeSinceEpochMicrosec();
    std::string order = ">";
    for (int i=0; i < rounds/2; i++) {
        ecall_search(eid, &randomNumbers[i], sizeof(randomNumbers[i]), order.c_str(), order.size());
    }
    order = "<";
    for (int i=rounds/2; i < rounds; i++) {
        ecall_search(eid, &randomNumbers[i], sizeof(randomNumbers[i]), order.c_str(), order.size());
    }
    t_end = timeSinceEpochMicrosec();
    std::cout << (t_end-t_start) << " us" << std::endl;
    

    // ecall_search(eid, &r, sizeof(r), order.c_str(), order.size());

	// for (int s_i = 0; s_i < 10; s_i++){
	// 	printf("\nSearching ==> %s\n", s_keyword[s_i].c_str());

    //     uint64_t t_start = timeSinceEpochMicrosec();
	// 	ecall_search(eid, s_keyword[s_i].c_str(), s_keyword[s_i].size());
    //     uint64_t t_end = timeSinceEpochMicrosec();
    //     std::cout << (t_end-t_start) << " us" << std::endl;
	// 	//printf("\n-> %llu\n", start - end);
	// }


	delete myClient;
	delete myServer;

	//destroy enclave
	ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);
	if (ret != SGX_SUCCESS)
	{
		printf("App: error %#x, failed to destroy enclave .\n", ret);
	}

	return 0;
}

