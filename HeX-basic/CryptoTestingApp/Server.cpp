#include "Server.h"
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <iostream>

Server::Server(){
  R_Doc.clear();
  M_I.clear();
}

Server::~Server(){
  R_Doc.clear();
  M_I.clear();
}

std::vector<std::string> Server::retrieve_edbs(label_struct* ins, size_t in_amt) {
	std::vector<std::string> res_list;
	for(int i = 0; i < in_amt; i++) {
		std::string label_string = std::string((char *) ins[i].content, ins[i].content_length);
		if(M_I.find(label_string) != M_I.end()) {
			res_list.push_back(M_I[label_string]);
		}
	}
	return res_list;
}

std::string Server::retrieve_edb(label_struct* ins) {
    // std::cout << "M_I " << M_I.size() << std::endl;
    // for ( auto it = M_I.begin(); it != M_I.end(); ++it ) {
    //     printf("%d\n", (it->first).length());
    //     printf("%d\n", (it->second).length());
    // }
    // std::cout << ins->content << std::endl;
    // std::cout << ins->content_length << std::endl;
	std::string label_string = std::string((char *) ins->content, ins->content_length);
    // std::cout << label_string << std::endl;
    
    if(M_I.find(label_string) == M_I.end()) {
        printf("Not found!\n");
    }

	std::string cipher_string = M_I[label_string];
    // std::cout << cipher_string << std::endl;
    M_I.erase(label_string);
	return cipher_string;
}

void Server::add_edbs(label_struct * outs, cipher_struct * outs_res, size_t out_amt) {
	for(int i = 0; i < out_amt; i++){
        std::string label((char*)outs[i].content, outs[i].content_length);
        std::string cipher((char*)outs_res[i].content, outs_res[i].content_length);
        M_I.insert(std::pair<std::string,std::string>(label,cipher));
    }
}

void Server::print_mem(){
    std::cout << (sizeof(std::string)+30000/8)*M_I.size() << std::endl;
}


void Server::ReceiveEncDoc(entry *encrypted_doc){
    
    std::string id(encrypted_doc->first.content, encrypted_doc->first.content_length);
    std::string enc_content(encrypted_doc->second.message, encrypted_doc->second.message_length);
    R_Doc.insert(std::pair<std::string,std::string>(id,enc_content));
  
}

void Server::ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 int pair_count){ 
  
	for(int indexTest = 0; indexTest < pair_count; indexTest++){

      std::string key1((char*)t1_u_arr[indexTest].content, t1_u_arr[indexTest].content_length);
      std::string value1((char*)t1_v_arr[indexTest].content, t1_v_arr[indexTest].content_length);

      M_I.insert(std::pair<std::string,std::string>(key1,value1));

    }
}

std::string Server::Retrieve_Encrypted_Doc(std::string del_id_str){                  
    return R_Doc.at(del_id_str);
}

void Server::Del_Encrypted_Doc(std::string del_id_str){
    R_Doc.erase(del_id_str); 
}

std::vector<std::string> Server::retrieve_query_results(rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,int pair_count){

    std::vector<std::string> Res;

    for(int indexTest = 0; indexTest < pair_count; indexTest++){
        
        std::string u_i((char*)Q_w_u_arr[indexTest].content, Q_w_u_arr[indexTest].content_length);
        std::string value = M_I.at(u_i);

        unsigned char *key = (unsigned char*)malloc(ENC_KEY_SIZE*sizeof(unsigned char));
        memcpy(key,Q_w_id_arr[indexTest].content,ENC_KEY_SIZE);

        int original_len;
            unsigned char *plaintext =(unsigned char*)malloc((value.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
            original_len= dec_aes_gcm((unsigned char*)value.c_str(),value.size(),key,plaintext);

        std::string doc_i((char*)plaintext,original_len);
        //printf("->%s",doc_i.c_str());
        
        //   Res.push_back(R_Doc.at(doc_i));
        Res.push_back(doc_i);

        //free
        free(plaintext);
        free(key);

    }

    // printf("%zu\n", Res.size());
    return Res;
}

//display utilities
void Server::Display_Repo(){

  printf("Display data in Repo\n");
  for ( auto it = R_Doc.begin(); it != R_Doc.end(); ++it ) {
    printf("Cipher\n");
    printf("%s\n", (it->first).c_str());
    print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_I(){

  std::unordered_map<std::string,std::string> ::iterator it;
  printf("Print data in M_I\n");
  for (it = M_I.begin(); it != M_I.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}
