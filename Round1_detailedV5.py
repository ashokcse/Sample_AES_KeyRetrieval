from collections import Counter
from itertools import groupby
import sys
import rm_missing_en as rm_en
import scoring as sc
import gc


scores=[]
no_highs=[]
#input is .bin file

total_encryptions=int(sys.argv[1])
ctxt_no=int(sys.argv[2])
first_n=sys.argv[3]

check_points_count=total_encryptions/5
check_points=[i*5 for i in range(1,check_points_count+1)]

Orig_keys=open('tmp/Round1_org_key.txt').readline()
Orig_keys=map(int,Orig_keys.strip('\n').split(','))

plain_txt_file='cipher_text/encrypted%d.bin'%ctxt_no

input_access_file='tmp/First_%s_access.txt'%first_n

detaiiled_key_file ='tmp/keys_detailed.txt'
key_stat ='tmp/results/R1_key_stat_%s.txt'%first_n
key_result='tmp/results/R1_result_%s.txt'%first_n
gen_results='tmp/round_1_results_%d.txt'%(total_encryptions)
key_bits_file='tmp/key_first_4bits.txt'
key_compar='tmp/key_compare_first_4bits.txt'
detail_result_file='tmp/round_1_detail._%d_%s.txt'%(total_encryptions,first_n)
mini_req_encrypt=[]
input_text=open(plain_txt_file,'r').read()
#print input_text

#list to have keys  prediction
pred_key=[]                 #stores pred keys
key_counts=[]               #stores key repeat count    
for i in range(0,16):
    pred_key.append([])
    key_counts.append([])
    
en_lst=[]
#Reading all Cache access data for all encryptions from file
all_cache_access=[]
for line in open(input_access_file,'r'):
    print set(line.split('[')[1][:-2].split(',')) 
    en_number=int(line.split(':')[0].split(' ')[1])
    en_lst.append(en_number)
    all_cache_access.append([ int(item) for item in line.split('[')[1][:-2].split(',')])
print len(all_cache_access)
#for ca in all_cache_access:
    #print ca
      
#List for storing pred key values 
pred_key=[]
key_counts=[]
for i in range(0,16):
    pred_key.append([])
    key_counts.append([])

key_occur_order=[]
for i in range(0,256):
    key_occur_order.append([])
    

#------------------------------------------------------------------------------#  
#Function to store key values and counts
def store_data(key_index, key_value):
    #print key_index, (key_index*16)+key_value
    if key_value in pred_key[key_index]:
        index_value=pred_key[key_index].index(key_value)
        #print index_value
        key_counts[key_index][index_value]=key_counts[key_index][index_value]+1
        #print key_index, key_value , key_counts[key_index][index_value]
    else:
        pred_key[key_index].append(key_value)
        key_counts[key_index].append(1)
        #print key_index, key_value , "1"
   # print "\n"    
     
    
#------------------------------------------------------------------------------#
#Get first 4 bit of input text
#int('{0:08b}'.format(ord('A'))[:4],2)

def get_first_4bits(char):
    int_char=ord(char) #Changing to ASCII value (int)
    bin_char='{0:08b}'.format(int_char)
    return int(bin_char[:4],2)                     

#------------------------------------------------------------------------------#

def prepare_results(idx,value_array):
    #print value_array
    start=idx*16
    end=start+16
    for i in range(start,end):
        if i%16 in value_array:
            key_occur_order[i].append(1)          
        else:
            key_occur_order[i].append(0)
        #print i,start,end,key_occur_order[i]
            
#------------------------------------------------------------------------------#
#It counts the first n occurence of key i.e. count first sucessive 1 
def get_con_occur(key_hits):
    count=0
    for key in key_hits:
        if key==1:
            count=count+1
        else:
            break
    return count
    
#------------------------------------------------------------------------------#
def find_index(lst,value):
    index=[]
    #print lst, value
    for idx, val in enumerate(lst):
        #print val, value
        if val==value:
            index.append(idx)
            
    return index
#------------------------------------------------------------------------------#
input_text=rm_en.remove_missing_cahce_txt(all_cache_access,input_text,en_lst)
#------------------------------------------------------------------------------#

# Input list.
text_index=0
for cache_access in all_cache_access[:total_encryptions]:
    #print "-------------------------------------"
    cache_access.sort()
    #print cache_access
    cache_access=list(set(cache_access))
    #print cache_access
    #Creating list for 4 table entries
    cache_access_Table=[]
    for i in range(0,4):
        cache_access_Table.append([])
        
    #seperating cache access by lookup-table    
    for item in cache_access:
        if item in range(0,16):
            cache_access_Table[0].append(item)
        elif item in range(16,32):
            cache_access_Table[1].append(item)
        elif item in range(32,48):
            cache_access_Table[2].append(item)
        elif item in range(48,64):
            cache_access_Table[3].append(item)
      
    #print ord(input_text[0])^cache_access_Table[0][1]
    #print cache_access_Table
    
    for idx, char in enumerate(input_text[text_index:text_index+16]):
        key_hits=[]
        for item in cache_access_Table[idx%4]:
            #print idx,char,item, ord(char)^item
            f4bit_char=get_first_4bits(char)
            #print item,idx,char, f4bit_char,"XOR",item%16, f4bit_char^(item%16), "--->T",idx%4
            store_data(idx,f4bit_char^(item%16))
            key_hits.append(f4bit_char^(item%16))
            #print idx,f4bit_char^(item%16)
        prepare_results(idx,key_hits)
    text_index=text_index+16
#------------------------------------------------------------------------------#   
#Storing Values in a file
orginal_key=open(detaiiled_key_file,'r')
output_file=open(gen_results,'w')
key_file=open(key_bits_file,'w')
key_c_file=open(key_compar,'w')
index=0
fin_key=[]
for key_list, count_list in  zip(pred_key, key_counts):
    output_file.write("\n\n--------Key %d-------------"%index)
    index=index+1
    common_key_values={}#py dict imp
    for key, count in zip(key_list, count_list):
        str1='{0:{width}}'.format(str(key),width=5)
        str2='{0:{width}}'.format('{0:04b}'.format(key),width=12)
        str3='{0:{width}}'.format(str(hex(key)),width=7)
        str4='{0:{width}}'.format(str(count),width=3)
        output_file.write("\n"+str1+str2+str3+str4)
        #Adding first 4 bits to find first 4 bits of key
        value=bin(key)[2:]
        value='{0:04b}'.format(key)
        #print value
        if value in common_key_values:   
            common_key_values[value]=common_key_values[value]+count
        else:
            common_key_values[value]=count
            
        #common_key_values.append(str(bin(key))[:6])
    #output_file.write(str(Counter(common_key_values).most_common(4)))
    sorted_common_keys=sorted(common_key_values.items(), key=lambda x:x[1],reverse=True)
    output_file.write(str(sorted_common_keys))
    #print sorted_common_keys[0][0]
    key_file.write(str(sorted_common_keys[0][0])+"\n")
    original_key_value=orginal_key.readline().strip('\n')
    key_c_file.write(str(sorted_common_keys[0][0])+"  "+str(hex(int(sorted_common_keys[0][0],2)))+" "+original_key_value+"\n")
    print '-->', sorted_common_keys[0][0],original_key_value
    fin_key.append(int(sorted_common_keys[0][0],2))
   
    #print common_key_values
    #print sorted(common_key_values.items(), key=lambda x:x[1],reverse=True)
    #print  pred_key
#print len(key_occur_order[100])
#------------------------------------------------------------------------------#
def print_detailed_results(check_points):
        global scores
        global mini_req_encrypt
        indiv_scores={}
        min_req_enc=[]#contains details send by get_con_occur(element) for each encryptions
        key_nu=0
        detail_io=open(detail_result_file,'w')
        for index, element in enumerate(key_occur_order):
            key_idx=index%16
            if key_idx == 0:
                if min_req_enc:
                    sort_min_req_enc=sorted(min_req_enc,reverse=True)
                    #print sort_min_req_enc
                    detail_io.write("\n\nkey  = %s #%s"%(find_index(min_req_enc,sort_min_req_enc[0]),sort_min_req_enc[0]))
                    detail_io.write("\nValue= %s #%s \t Min Req Enc = %s\n"%(find_index(min_req_enc,sort_min_req_enc[1]),sort_min_req_enc[1],int(sort_min_req_enc[1])+1))
                    mini_req_encrypt.append(int(sort_min_req_enc[1])+1)
                
                detail_io.write("\n#----------Key %d -------------#"%key_nu)
                key_nu=key_nu+1
                min_req_enc=[]
                scores.append(indiv_scores)
                #print '++++'
                #print indiv_scores
                indiv_scores={}
            str1='{0:{width}}'.format(str(key_idx),width=5)
            str2='{0:{width}}'.format('{0:04b}'.format(key_idx),width=12)
            str3='{0:{width}}'.format(str(hex(key_idx)),width=7)
            str4=str(element).replace('0','_').replace(',','')
            #-------------------------------------------------------#            
            indiv_scores[key_idx]=element
            #print indiv_scores
            #print '====='
            
            #-------------------------------------------------------#
            str5='{:5}'.format(element.count(1))
            str6=''
            for check_point in check_points:
                str6_tmp='{:4}'.format(element[:check_point].count(1))
                str6=str6+' '+str6_tmp
            str6=str6+' '
            occ_count=get_con_occur(element)
            str7='{:4}'.format(occ_count)
            min_req_enc.append(occ_count)
            detail_io.write("\n"+str1+str2+str3+str4+str5+str6)
            #detail_io.write("\n"+str1+str2+str3+str(element[:10].count(1))+""+str(element).replace('0','_').replace(',','')+" "+str(element.count(1))+" ")
            


        if min_req_enc:            
            scores.append(indiv_scores)
            print '++++'
            indiv_scores={}
            sort_min_req_enc=sorted(min_req_enc,reverse=True)
            #print min_req_enc
            detail_io.write("\n\nkey  = %s #%s"%(min_req_enc.index(sort_min_req_enc[0]),sort_min_req_enc[0]))
            detail_io.write("\nValue= %s #%s \t Min Req Enc = %s\n"%(min_req_enc.index(sort_min_req_enc[1]),sort_min_req_enc[1],int(sort_min_req_enc[1])+1))
        detail_io.close()

print_detailed_results(check_points)

#------------------------------------------------------------------------------#
result=open('tmp/Rount1_counts.txt','a')	
#------------------------------------------------------------------------------#
for ix, value in enumerate(mini_req_encrypt):			
    result.write(str(ix)+','+str(value)+'\n')			
result.write('Minimum Encrypt Required: '+str(max(mini_req_encrypt)))			
result.close()			
			
print mini_req_encrypt, max(mini_req_encrypt)			
			
#with open("all_results/round1_keys.txt", "a") as myfile:			
#    myfile.write(str(sample_set)+':'+str([hex(i) for i in fin_key]).replace(r'\'', '')+':'+str(max(mini_req_encrypt))+'\n')			
print fin_key    


#------------------------------------------------------------------------------#
#sending for scoring
print len(scores)
fin_key_1=[]
min_req_enc_1=[]
diff=[]
for ix,item in enumerate(scores[1:]):
    #print '----------------',ix
    (min_enq,key_value,dif)=sc.check_scores(item,4,total_encryptions)
    fin_key_1.append(key_value)
    min_req_enc_1.append(min_enq)
    diff.append(dif)
#    
#    #print item
#    for i in item:
#        print i, item[i]
#sc.check_scores(scoreboards)
print fin_key
print 'D--->',fin_key_1
print 'o--->', Orig_keys
print mini_req_encrypt, max(mini_req_encrypt)			
print min_req_enc_1, max(min_req_enc_1)			
open(key_stat,'w').write(str(min_req_enc_1)+":"+str(diff))

#if fin_key==fin_key_1:
if Orig_keys==fin_key_1:
    print 'True'
    open(key_result,'w').write(str(max(min_req_enc_1)))
else:
    open(key_result,'w').write(str(total_encryptions))
gc.collect()
