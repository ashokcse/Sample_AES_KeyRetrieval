import os
import multiprocessing as mp
import tables
import itertools
import math
import sys
#import pandas as pd
from numpy import array
from datetime import datetime
import rm_missing_en as rm_en
import scoring as sc
import gc
os.system("taskset -p 0xff %d" % os.getpid())

No_of_Encyption=int(sys.argv[1])
first_n=sys.argv[2]
No_of_combine_Encryptions=No_of_Encyption
ctxt_no=int(sys.argv[3])
#No_of_min_sucess=int(sys.argv[4])
No_of_min_sucess=int(sys.argv[4])

min_req_decrypt=[]

len_t=[[] for i in range(4)]
dcyp_reduce_count=[[],[],[],[]]#0 for i in range(No_of_Encyption)]
eq_set_ord={2:[4,1,14,11],3:[8,5,2,15],4:[12,9,6,3]}
found_from_decy=[]
run_size=[]
cache_line_counts=[]
u_run_size=[]
success=0
keys_found=[]
#-------------------INputs -------------------------------------------------#
tmp_out=open('tmp/s2_1.txt','w') 

cyp_txt='cipher_text/encrypted%d.bin'%ctxt_no
cyp_txt_file=open(cyp_txt,'r') 
key_first_4bits_file='tmp/key_first_4bits.txt'
key_stat='tmp/results/R2_key_stat_%s.txt'%first_n
key_rst='tmp/results/R2_minrq_%s.txt'%first_n

input_access_file='tmp/First_%s_access.txt'%first_n

#stat_file=open('%s/stat_all_%s.txt'%(sample_set,No_of_Encyption),'w')
#stat_file_dec=open('%s/stat_alg2_decy.txt'%sample_set,'w')    
#----------------------------------------------------------------------#
#original key
keys=open('tmp/round_key10.txt').readline()
keys=keys.strip('\n').split(',')
print keys 
real_keys=[]
for i in keys:
    real_keys.append(int(i,16))
print real_keys

#------------------------------------------------------------------------------------------------#
def conv2DataFrame(allElement):
    data_frams=[]
    for index, elemt in enumerate(allElement):
        data={}
        for i in equation_key_order[index]:
            data[i]=[]
            #print i
        for item in elemt:
            for idx, i in enumerate(equation_key_order[index]):
                data[i].append(item[idx])                        
        #for i in equation_key_order[index]:
        #        print len(data[i])    
        data_frams.append(pd.DataFrame(data))
    return data_frams
#------------------------------------------------------------------------------------------------#
#----------------------------bInitial values--------------------------------#

cyptxt=[]
'''
for line in cyp_txt_file:
    v=''
    #print str(line).strip() 
    line=str(line).replace(" ", "").strip('\n')
    for i,item in enumerate(line):
        if item: 
           v=v+item
           if i%2==1:
               v=v+' '
    #print v.split() 
    for value in v.split():
        cyptxt.append('0x'+value)
#print input_text
plain_txt=[chr(int(i,16)) for i in cyptxt]'''

plain_txt=cyp_txt_file.read()

keys_msb=[int(x.strip('\n'),2) for x in open(key_first_4bits_file,'r')]
#Reading all Cache access data for all encryptions from file
all_cache_access=[]
en_lst=[]
for line in open(input_access_file,'r'):
    #print set(line.split('[')[1][:-2].split(','))
    en_number=int(line.split(':')[0].split(' ')[1])
    en_lst.append(en_number) 
    all_cache_access.append([ int(item) for item in line.split('[')[1][:-2].split(',')])

all_cache_access=all_cache_access[:No_of_Encyption]
Total_encrytions=len(all_cache_access)
#------------------------------------------------------------------------------#
plain_txt=rm_en.remove_missing_cahce_txt(all_cache_access,plain_txt,en_lst)
#------------------------------------------------------------------------------#



#S-box items
s=tables.get_sbox()
#S-Inverse box item
si=tables.get_inv_sbox() 
si=[int(i,16)for i in si]
#GF-Multiplicatin by 9
i9=tables.get_9box()
i9=[int(i,16)for i in i9]
#GF-Multiplicatin by b
b=tables.get_bbox()
b=[int(i,16)for i in b]
#GF-Multiplicatin by d
d=tables.get_dbox()
d=[int(i,16)for i in d]
#GF-Multiplicatin by e
e=tables.get_ebox()
e=[int(i,16)for i in e]



x=range(16)
#------------------------------------------------------------------------------#     
 
def compute_key_set(keyset):
    #print '--------------------'
    combinations =["".join(seq) for seq in itertools.product("01", repeat=4)]
    key_combinations=[]
    for key_item in keyset:
        #print key_item
        Temp=[]
        for item in combinations:
            Temp.append(int((bin(key_item)+item),2))
        #print Temp
        key_combinations.append(Temp)
    #print '--------------------'
    return key_combinations
#----------------------------------------------------------------------- ------# 
def combine_two_keys_for_GF(key1,key2):
    k1k2=key1^key2
    #print key1,key2,k1k2 
    combinations =["".join(seq) for seq in itertools.product("01", repeat=3)]
    first_4_bits='{0:08b}'.format(k1k2)[:-4]
    lst=[int(first_4_bits+i+'0',2) for i in combinations]
    #print list 
    return lst

#------------------------------------------------------------------------------#
def get_table_vise_data(cache_line):
    cache_access=cache_line

    cache_access.sort()
    #print cache_access
    cache_access=list(set(cache_access))
    #print cache_access
    #Creating list for 4 table entries
    cache_access_Table=[]
    for i in range(0,4):
        cache_access_Table.append([])
    #seperating cache access by lookup-table    
    #seperating cache access by lookup-table    
    for item in cache_access:
        if item in range(0,16):
             cache_access_Table[0].append(item)
        elif item in range(16,32):
             cache_access_Table[1].append(item%16)
        elif item in range(32,48):
             cache_access_Table[2].append(item%16)
        elif item in range(48,64):
             cache_access_Table[3].append(item%16)
    #print cache_access_Table 
    for ix,i in enumerate (cache_access_Table):
        i.sort()
        len_t[ix].append(len(i))
    return cache_access_Table 

#------------------------------------------------------------------------------# 
def co_solve_equatio_4567(first_key_element,co_cache,co_cyp_txt,key_set):
    x=co_cache 
    stat_set={}
    stats=[]
    stat_join=[]
    stat_j1=[]
    stat_j2=[]
    test=[[],[],[],[]]
    no_of_ce=len(co_cyp_txt)
    for i in range(len(co_cyp_txt)):
        stat_join.append(0)
        stat_j1.append(0)
        stat_j2.append(0)
        stats.append([0,0,0,0])
    i=0;j=0;k=0
    possible_values_all=[]        
    k0k4=combine_two_keys_for_GF(key_set[0][0],key_set[4][0])[0]
    k1k5=combine_two_keys_for_GF(key_set[1][0],key_set[5][0])[0]
    k2k6=combine_two_keys_for_GF(key_set[2][0],key_set[6][0])[0]
    k3k7_list=combine_two_keys_for_GF(key_set[3][0],key_set[7][0])
    stat_count=-1
    t_count=0
    for k4 in first_key_element:#key_set[4]:
        for k1 in key_set[1]:
            for k14 in key_set[14]:
                for k11 in key_set[11]:
                            for k3k7 in k3k7_list:
                                eq_1=(e[k0k4]) ^(b[k1k5]) ^(d[k2k6]) ^(i9[k3k7])
                                eq_2=(i9[k0k4])^(e[k1k5]) ^(b[k2k6]) ^(d[k3k7])
                                eq_3=(d[k0k4]) ^(i9[k1k5])^(e[k2k6]) ^(b[k3k7])
                                eq_4=(b[k0k4]) ^(d[k1k5]) ^(i9[k2k6])^(e[k3k7])
                                y1=int('{0:08b}'.format(eq_1)[:-4],2)
                                y2=int('{0:08b}'.format(eq_2)[:-4],2)
                                y3=int('{0:08b}'.format(eq_3)[:-4],2)
                                y4=int('{0:08b}'.format(eq_4)[:-4],2)
                                matches=True
                                stat_count=-1
                                equ=[0,0,0,0]
        			#
				sz=len(co_cyp_txt)
				stat_tmp=[[0]*sz,[0]*sz,[0]*sz,[0]*sz,]
	        		#
                                succs=[]
                                for c,x in zip(co_cyp_txt,co_cache):
                                       stat_count=stat_count+1
                                       #if matches==True:   #if a tuple fails in any decrytion it wont go for next 
                                       matches=False                                        
                                       #print k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7,len(x[0]),len(x[1]),len(x[2]),len(x[3])
                                       eq1=False;eq2=False;eq3=False;eq4=False
                                       x4 = (e[si[c[4]^k4]]) ^(b[si[c[1]^k1]]) ^(d[si[c[14]^k14]]) ^(i9[si[c[11]^k11]])^eq_1
                                       x5 = (i9[si[c[4]^k4]])^(e[si[c[1]^k1]]) ^(b[si[c[14]^k14]]) ^(d[si[c[11]^k11]]) ^eq_2
                                       x6 = (d[si[c[4]^k4]]) ^(i9[si[c[1]^k1]])^(e[si[c[14]^k14]]) ^(b[si[c[11]^k11]]) ^eq_3
                                       x7 = (b[si[c[4]^k4]]) ^(d[si[c[1]^k1]]) ^(i9[si[c[14]^k14]])^(e[si[c[11]^k11]]) ^eq_4
                                       x00=int('{0:08b}'.format(x4)[:-4],2)
                                       x11=int('{0:08b}'.format(x5)[:-4],2)
                                       x22=int('{0:08b}'.format(x6)[:-4],2)
                                       x33=int('{0:08b}'.format(x7)[:-4],2)
                                       if x00  in x[0]:
				            stat_tmp[0][stat_count]=1
				       if x11  in x[1]:
					    stat_tmp[1][stat_count]=1
				       if x22  in x[2]:
				            stat_tmp[2][stat_count]=1
				       if x33  in x[3]:
				            stat_tmp[3][stat_count]=1

                                #if equ[0]>No_of_min_sucess and equ[1]>No_of_min_sucess and equ[2]>No_of_min_sucess and equ[3]>No_of_min_sucess:
                                #    stat_set[str([k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                                stat_set_count=[stat_tmp[i].count(1) for i in range(4)]
                                if min(stat_set_count) > No_of_min_sucess:
                                        stat_set[str([k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
									
                                #if matches==True:
                                #   possible_values_all.append([k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7])
                                #   #print i
    #return [possible_values_all,stats,stat_join,test,stat_j1,stat_j2,stat_set]  
    return  stat_set 
#------------------------------------------------------------------------------# 

#------------------------------------------------------------------------------# 
def co_solve_equatio_891011(first_key_element,co_cache,co_cyp_txt,key_set):
    x=co_cache 
    stats=[]
    stat_join=[]
    stat_set={}
    stat_j1=[]
    stat_j2=[]
    test=[[],[],[],[]]
    no_of_ce=len(co_cyp_txt)
    for i in range(len(co_cyp_txt)):
        stat_join.append(0)
        stat_j1.append(0)
        stat_j2.append(0)
        stats.append([0,0,0,0])
    #exp_value=[16, 85, 170, 255]
    i=0;j=0;k=0
    possible_values_all=[]        
    k4k8=combine_two_keys_for_GF(key_set[4][0],key_set[8][0])[0]
    k5k9=combine_two_keys_for_GF(key_set[5][0],key_set[9][0])[0]
    k6k10=combine_two_keys_for_GF(key_set[6][0],key_set[10][0])[0]
    k7k11_list=combine_two_keys_for_GF(key_set[7][0],key_set[11][0])
    
    t_count=0
    for k8 in first_key_element:#key_set[8]:
        for k5 in key_set[5]:
            for k2 in key_set[2]:
                for k15  in key_set[15]:
                                for k7k11 in k7k11_list:
                                    eq_1=(e[k4k8]) ^(b[k5k9]) ^(d[k6k10]) ^(i9[k7k11])
                                    eq_2=(i9[k4k8])^(e[k5k9]) ^(b[k6k10]) ^(d[k7k11])
                                    eq_3=(d[k4k8]) ^(i9[k5k9])^(e[k6k10]) ^(b[k7k11])
                                    eq_4=(b[k4k8]) ^(d[k5k9]) ^(i9[k6k10])^(e[k7k11])
                                    y1=int('{0:08b}'.format(eq_1)[:-4],2)
                                    y2=int('{0:08b}'.format(eq_2)[:-4],2)
                                    y3=int('{0:08b}'.format(eq_3)[:-4],2)
                                    y4=int('{0:08b}'.format(eq_4)[:-4],2)
                                    t_count=t_count+1
                                    matches=True
                                    stat_count=-1
                                    equ=[0,0,0,0]
                                    #
                                    sz=len(co_cyp_txt)
                                    stat_tmp=[[0]*sz,[0]*sz,[0]*sz,[0]*sz,]
                                    #
                                    succs=[]
                                    for c,x in zip(co_cyp_txt,co_cache):
                                               stat_count=stat_count+1
                                               #if matches==True:
                                               matches=False                                        
                                               eq1=False;eq2=False;eq3=False;eq4=False
                                               #print k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7,len(x[0]),len(x[1]),len(x[2]),len(x[3])
                                               x8 = (e[si[c[8]^k8]]) ^(b[si[c[5]^k5]]) ^(d[si[c[2]^k2]]) ^(i9[si[c[15]^k15]])^eq_1
                                               x9 = (i9[si[c[8]^k8]])^(e[si[c[5]^k5]]) ^(b[si[c[2]^k2]]) ^(d[si[c[15]^k15]]) ^eq_2
                                               x10 = (d[si[c[8]^k8]]) ^(i9[si[c[5]^k5]])^(e[si[c[2]^k2]]) ^(b[si[c[15]^k15]]) ^eq_3
                                               x11 = (b[si[c[8]^k8]]) ^(d[si[c[5]^k5]]) ^(i9[si[c[2]^k2]])^(e[si[c[15]^k15]]) ^eq_4
                                               x00=int('{0:08b}'.format(x8)[:-4],2)
                                               x01=int('{0:08b}'.format(x9)[:-4],2)
                                               x22=int('{0:08b}'.format(x10)[:-4],2)
                                               x33=int('{0:08b}'.format(x11)[:-4],2)
                                               if x00  in x[0]:
                                                    stat_tmp[0][stat_count]=1
                                               if x01  in x[1]:
                                                    stat_tmp[1][stat_count]=1
                                               if x22  in x[2]:
                                                    stat_tmp[2][stat_count]=1
                                               if x33  in x[3]:
                                                    stat_tmp[3][stat_count]=1

                                    #if equ[0]>No_of_min_sucess and equ[1]>No_of_min_sucess and equ[2]>No_of_min_sucess and equ[3]>No_of_min_sucess:
                                    stat_set_count=[stat_tmp[i].count(1) for i in range(4)]
                                    if min(stat_set_count) > No_of_min_sucess:	
                                        stat_set[str([k8,k5,k2,k15,k4k8,k5k9,k6k10,k7k11])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                                        #print [stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                                    #if len(succs)==no_of_ce:
                                    #   possible_values_all.append([k8,k5,k2,k15,k4k8,k5k9,k6k10,k7k11])
    #return [possible_values_all,stats,stat_join,test,stat_j1,stat_j2,stat_set]                            
    return  stat_set
#------------------------------------------------------------------------------# 

#------------------------------------------------------------------------------# 
def co_solve_equatio_12131415(first_key_element,co_cache,co_cyp_txt,key_set):
    x=co_cache 
    stats=[]
    stat_set={}
    stat_join=[]
    stat_j1=[]
    stat_j2=[]
    test=[[],[],[],[]]
    no_of_ce=len(co_cyp_txt)
    for i in range(len(co_cyp_txt)):
        stat_join.append(0)
        stat_j1.append(0)
        stat_j2.append(0)
        stats.append([0,0,0,0])
    possible_values_all=[]        
    k8k12=combine_two_keys_for_GF(key_set[8][0],key_set[12][0])[0]
    k9k13=combine_two_keys_for_GF(key_set[9][0],key_set[13][0])[0]
    k10k14=combine_two_keys_for_GF(key_set[10][0],key_set[14][0])[0]
    k11k15_list=combine_two_keys_for_GF(key_set[11][0],key_set[15][0])
    #print k8k12_list
    #print k9k13_list
    #print k10k14_list
    #print k11k15_list 
    for k12 in first_key_element:#key_set[4]:
        for k9 in key_set[9]:
            for k6 in key_set[6]:
                for k3 in key_set[3]:
                    for k11k15 in k11k15_list:
                        eq_1=(e[k8k12]) ^(b[k9k13]) ^(d[k10k14]) ^(i9[k11k15])
                        eq_2=(i9[k8k12])^(e[k9k13]) ^(b[k10k14]) ^(d[k11k15])
                        eq_3=(d[k8k12]) ^(i9[k9k13])^(e[k10k14]) ^(b[k11k15])
                        eq_4=(b[k8k12]) ^(d[k9k13]) ^(i9[k10k14])^(e[k11k15])
                        y1=int('{0:08b}'.format(eq_1)[:-4],2)
                        y2=int('{0:08b}'.format(eq_2)[:-4],2)
                        y3=int('{0:08b}'.format(eq_3)[:-4],2)
                        y4=int('{0:08b}'.format(eq_4)[:-4],2)
                        matches=True
                        stat_count=-1
                        equ=[0,0,0,0]
                        #
                        sz=len(co_cyp_txt)
                        stat_tmp=[[0]*sz,[0]*sz,[0]*sz,[0]*sz,]
                        #
                        succs=[]
                        for c,x in zip(co_cyp_txt,co_cache):
                                stat_count=stat_count+1
                                #if matches==True:
                                matches=False  
                                eq1=False;eq2=False;eq3=False;eq4=False                                    
                                #print k12,k9,k6,k3,k8k12,k9k13,k10k14,k11k15,len(x[0]),len(x[1]),len(x[2]),len(x[3])
                                x12 = (e[si[c[12]^k12]]) ^(b[si[c[9]^k9]]) ^(d[si[c[6]^k6]]) ^(i9[si[c[3]^k3]])^eq_1
                                x13 = (i9[si[c[12]^k12]])^(e[si[c[9]^k9]]) ^(b[si[c[6]^k6]]) ^(d[si[c[3]^k3]]) ^eq_2
                                x14 = (d[si[c[12]^k12]]) ^(i9[si[c[9]^k9]])^(e[si[c[6]^k6]]) ^(b[si[c[3]^k3]]) ^eq_3
                                x15 = (b[si[c[12]^k12]]) ^(d[si[c[9]^k9]]) ^(i9[si[c[6]^k6]])^(e[si[c[3]^k3]]) ^eq_4
                                x00=int('{0:08b}'.format(x12)[:-4],2)
                                x11=int('{0:08b}'.format(x13)[:-4],2)
                                x22=int('{0:08b}'.format(x14)[:-4],2)
                                x33=int('{0:08b}'.format(x15)[:-4],2)
                                if x00  in x[0]:
                                    stat_tmp[0][stat_count]=1
                                    #print '0',
                                if x11  in x[1]:
                                    stat_tmp[1][stat_count]=1
                                    #print '1',
                                if x22  in x[2]:
                                    stat_tmp[2][stat_count]=1
                                    #print '2',
                                if x33  in x[3]:
                                    stat_tmp[3][stat_count]=1
                                    #print '3',

                        #if equ[0]>No_of_min_sucess and equ[1]>No_of_min_sucess and equ[2]>No_of_min_sucess and equ[3]>No_of_min_sucess:
                        stat_set_count=[stat_tmp[i].count(1) for i in range(4)]
                        
                        if min(stat_set_count) > No_of_min_sucess:
    
                                    stat_set[str([k12,k9,k6,k3,k8k12,k9k13,k10k14,k11k15])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                        if matches==True:
                                #x12 = (e[si[c[12]^k12]]) ^(b[si[c[9]^k9]]) ^(d[si[c[6]^k6]]) ^(i9[si[c[3]^k3]])^(e[k8k12]) ^(b[k9k13]) ^(d[k10k14]) ^(i9[k11k15])
                                #x13 = (i9[si[c[12]^k12]])^(e[si[c[9]^k9]]) ^(b[si[c[6]^k6]]) ^(d[si[c[3]^k3]]) ^(i9[k8k12])^(e[k9k13]) ^(b[k10k14]) ^(d[k11k15])
                                #x14 = (d[si[c[12]^k12]]) ^(i9[si[c[9]^k9]])^(e[si[c[6]^k6]]) ^(b[si[c[3]^k3]]) ^(d[k8k12]) ^(i9[k9k13])^(e[k10k14]) ^(b[k11k15])
                                #x15 = (b[si[c[12]^k12]]) ^(d[si[c[9]^k9]]) ^(i9[si[c[6]^k6]])^(e[si[c[3]^k3]]) ^(b[k8k12]) ^(d[k9k13]) ^(i9[k10k14])^(e[k11k15])
                           #possible_values_all.append([k12,k9,k6,k3,k8k12,k9k13,k10k14,k11k15])
                           #print i
                           i=i+1

    #return [possible_values_all,stats,stat_join,test,stat_j1,stat_j2,stat_set]  
    return  stat_set
#------------------------------------------------------------------------------# 

key_sets=compute_key_set(keys_msb)  
print '=================================='
for i,x in enumerate(key_sets):
        print i, x 
print '++++++++++++++'

#------------------------------Combining encrypitons---------------------------# 
cy_txt=plain_txt[:]
co_cache_access=[]
co_cypter_txt=[]
for co_eny in range(No_of_combine_Encryptions):
    co_cache_access.append(get_table_vise_data(all_cache_access[co_eny]))
    co_cypter_txt.append(map(ord,cy_txt[:16]))
    cy_txt=cy_txt[16:]


#------------------------------------------------------------------------------# 

def co_solve_equatio_1234_y(first_key_element,co_cache,co_cyp_txt,key_set,other_sets):
    
    combinations =["".join(seq) for seq in itertools.product("01", repeat=4)]
    #z4_lst=[int('000'+i+'0',2) for i in combinations]
    z4_lst=[int(i+'0000',2) for i in combinations]   
    x=co_cache 
    stat_set={}
    stats=[]
    stat_j2=[]
    stat_j1=[]
    stat_join=[]
    z4=-1
    test=[[],[],[],[]]
    no_of_ce=len(co_cyp_txt)
    for i in range(len(co_cyp_txt)):
        stat_join.append(0)
        stat_j2.append(0)
        stat_j1.append(0)
        stats.append([0,0,0,0])
    i=0;j=0;k=0

    #print first_key_element,z4_lst
    possible_values_all=[]  
    for k0 in first_key_element:#key_set[0]:
        for k13 in key_set[13]:            
            for k10 in key_set[10]:
                for k7 in key_set[7]:  
                    for k in other_sets: 
                        eq_1=(e[k0^(s[k[9]^k13])^0x36])^(b[k[1]^(s[k10^k[14]])])^(d[k[2]^(s[k[11]^k[15]])])^(i9[k[3]^(s[k[8]^k[12]])])
                        eq_2=(i9[k0^(s[k[9]^k13])^0x36])^(e[k[1]^(s[k10^k[14]])])^(b[k[2]^(s[k[11]^k[15]])])^(d[k[3]^(s[k[8]^k[12]])]) # (i9[0])^(e[0])^(b[0])^(d[z4])
                        eq_3=(d[k0^(s[k[9]^k13])^0x36])^(i9[k[1]^(s[k10^k[14]])])^(e[k[2]^(s[k[11]^k[15]])])^(b[k[3]^(s[k[8]^k[12]])]) #(d[0])^(i9[0])^(e[0])^(b[z4])
                        eq_4=(b[k0^(s[k[9]^k13])^0x36])^(d[k[1]^(s[k10^k[14]])])^(i9[k[2]^(s[k[11]^k[15]])])^(e[k[3]^(s[k[8]^k[12]])]) #(b[0])^(d[0])^(i9[0])^(e[z4])   
                        y1=y2=y3=y4=int('{0:08b}'.format(z4)[:-4],2)         
                        matches=True						
                        #
                        sz=len(co_cyp_txt)
                        stat_tmp=[[0]*sz,[0]*sz,[0]*sz,[0]*sz,]
                        #
                        stat_count=-1
                        equ=[0,0,0,0]
                        tmp1=[];tmp2=[];tmp3=[];tmp0=[]
                        for c,x in zip(co_cyp_txt,co_cache):
                                stat_count=stat_count+1
                                #if matches==True:
                                matches=False 
                                eq1=False;eq2=False;eq3=False;eq4=False 
                                x0 =(e[si[c[0]^k0]]) ^(b[si[c[13]^k13]]) ^(d[si[c[10]^k10]]) ^(i9[si[c[7]^k7]])^eq_1
                                x1 =(i9[si[c[0]^k0]])^(e[si[c[13]^k13]]) ^(b[si[c[10]^k10]]) ^(d[si[c[7]^k7]]) ^eq_2
                                x2 =(d[si[c[0]^k0]]) ^(i9[si[c[13]^k13]])^(e[si[c[10]^k10]]) ^(b[si[c[7]^k7]]) ^eq_3
                                x3 =(b[si[c[0]^k0]]) ^(d[si[c[13]^k13]]) ^(i9[si[c[10]^k10]])^(e[si[c[7]^k7]]) ^eq_4
                                x00=int('{0:08b}'.format(x0)[:-4],2)
                                x11=int('{0:08b}'.format(x1)[:-4],2)
                                x22=int('{0:08b}'.format(x2)[:-4],2)
                                x33=int('{0:08b}'.format(x3)[:-4],2)
                                if x00  in x[0]:
                                    stat_tmp[0][stat_count]=1
                                if x11  in x[1]:
                                    stat_tmp[1][stat_count]=1
                                if x22  in x[2]:
                                    stat_tmp[2][stat_count]=1
                                if x33  in x[3]:
                                    stat_tmp[3][stat_count]=1
                                
     
  
                        #if equ[0]>No_of_min_sucess and equ[1]>No_of_min_sucess and equ[2]>No_of_min_sucess and equ[3]>No_of_min_sucess:
                        stat_set_count=[stat_tmp[i].count(1) for i in range(4)]
                        #print stat_set_count, min(stat_set_count), No_of_min_sucess
                        #print [k0,k13,k10,k7,z4],stat_set_count, min(stat_set_count),No_of_min_sucess
                        if min(stat_set_count) > No_of_min_sucess:
                                    #stat_set[str([k0,k13,k10,k7,z4])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                                    stat_set[str([k0,k[1],k[2],k[3],k[4],k[5],k[6],k7,k[8],k[9],k10,k[11],k[12],k13,k[14],k[15]])]=[stat_tmp[0],stat_tmp[1],stat_tmp[2],stat_tmp[3]]
                                    #print '--->',stat_set_count, min(stat_set_count), No_of_min_sucess
                        #if matches==True:
                        #   possible_values_all.append([k0,k13,k10,k7,z4])
                        #   i=i+1
    #return [possible_values_all,stats,stat_join,stat_j1,stat_j2] 
    #print len(possible_values_all)
    #return [possible_values_all,stats,stat_join,test,stat_j1,stat_j2,stat_set]   
    return  stat_set
#------------------------------------------------------------------------------# 
#------------------------------------------------------------------------------# 
pool = mp.Pool(processes=8)

print "=-============================="

results = [pool.apply_async(co_solve_equatio_4567, args=(key_sets[4][i:i+1],co_cache_access,co_cypter_txt,key_sets,)) for i in range(16)]# if i%2==0]
output = [p.get() for p in results]
del results
pool.close()
pool.join()
del pool
gc.collect()
os.system('sync; echo 3 > /proc/sys/vm/drop_caches')
pool = mp.Pool(processes=7)
print '111'
results1 = [pool.apply_async(co_solve_equatio_891011, args=(key_sets[8][i:i+1],co_cache_access,co_cypter_txt,key_sets,)) for i in range(16)]# if i%2==0]
output1 = [p.get() for p in results1]
del results1
print '222'
pool.close()
pool.join()
del pool
gc.collect()
os.system('sync; echo 3 > /proc/sys/vm/drop_caches')
pool = mp.Pool(processes=7)
results2 = [pool.apply_async(co_solve_equatio_12131415, args=(key_sets[12][i:i+1],co_cache_access,co_cypter_txt,key_sets,)) for i in range(16)]# if i%2==0]
output2 =[p.get() for p in results2]
del results2
print '333'
pool.close()
pool.join()
del pool
gc.collect()
os.system('sync; echo 3 > /proc/sys/vm/drop_caches')

#output=[]
#output2=[]
print len(output2)
totals=[]
all_sets=[]
j1=[];j2=[]
all_equ=[]
stat_equ=[]
stata_join_all=[]
all_jns=[]
all_data_set=[]
#---------------------Free Memory---------------------#  

#del results1
#del results2
#del results4x
gc.collect()
#------------------------------------------------------#
def collect_datas(output):
    tmp_set={}
    for value in output:
        tmp_set.update(value)
    return tmp_set      
        
#------------------------------------------------------#
for st,opt in enumerate([output,output1,output2]):#,output4x]):
    tmp_sets=collect_datas(opt)
    all_sets.append(tmp_sets)
print "======****************=========="       

print "======****************=========="   
print '->', len( all_jns)
#print all_jns[-1]
print '->'
#---------------------Free Memory---------------------#
del output
del output1
del output2
#del output4x
gc.collect()
#------------------------------------------------------#
def duplicates(lst, item):
   return [i for i, x in enumerate(lst) if x == item]
#-----------------Counting Function-------------------------------#
def count_key_score(values):
    all_scores=[]
    key_values=[]
    #print values
    print '--Counting Key Score--'
    for item in values:
        key_values.append(item)
        tmp=[i.count(1) for i in values[item]]		
        #print item , tmp , sum(tmp)	
        all_scores.append(sum(tmp))		
    sorted_total_scores=sorted(list(set(all_scores)))
    #--------------------------------------------#
    top_score=sorted_total_scores[-1]
    try:
       next_top_score=sorted_total_scores[-2]
    except:
        next_top_score=0
    top_scores_diff=top_score-next_top_score
    #--------------------------------------------#
    occurence_top_score= duplicates(all_scores,top_score)
    occurence_next_top_score=duplicates(all_scores,next_top_score)
    no_of_occurence_top_score=len(occurence_top_score)  #all_scores.count(top_score)
    no_of_occurence_next_top_score=len(occurence_next_top_score)    #all_scores.count(next_top_score)
    #--------------------------------------------# 'Status-', sorted_total_scores
    print 'Top', top_score, no_of_occurence_top_score
    set_values=[]
    for item in occurence_top_score:
        value=key_values[item]
        set_values.append(value)
        print value, [i.count(1) for i in values[value]], values[value]
    #sets_values.append(tmp)
    print set_values
    sets_max=[[top_score,no_of_occurence_top_score],[next_top_score,no_of_occurence_next_top_score]]
    print 'NExt Top',next_top_score, no_of_occurence_next_top_score
    #for item in occurence_next_top_score:
    #    print key_values[top_s_index]
    return (set_values, sets_max)
    

#-----------------------------------------------------------------#

#-----------------Counting-------------------------------#

#all_sets
sets_values=[] #having key values with max counts
sets_max=[]
eqset1=[[],[],[],[]]
eqset2=[[],[],[],[]]
eqset3=[[],[],[],[]]
eqset4=[[],[],[],[]]

eqsets=[eqset3,eqset3,eqset4,eqset1]

Final_scored_keys=[]
all_diff=[]
print str(datetime.now())

#---------------------------------------------------------------------------#
#results_cs = [pool.apply_async(sc.check_scores_4,args=(values,No_of_min_sucess,Total_encrytions,ix+2))for ix,values in enumerate(all_sets) ]
#output_cs= [p.get() for p in results_cs]
#s1=collect_datas(output_cs)
#print s1
#---------------------------------------------------------------------------#
print str(datetime.now())
for ix,values in enumerate(all_sets):
    
    #(set_values, sets_max)=count_key_score(values)
    #print '--->----', set_values
    #print '--->----', sets_max
    (min_enq,key_value_11,dif)=sc.check_scores_4(values,No_of_min_sucess,Total_encrytions,ix+2)
    print min_enq
    print key_value_11
    print dif
    all_diff.append(dif)
    min_req_decrypt.append(min_enq)
    #sets_values.append(set_values)
    sets_values.append([key_value_11])
    #sets_max.append(sets_max)
print str(datetime.now())   
#------------------------------------------------------#

#Calculating set-1 values
#set2->k4,k1,k14,k11,k0k4,k1k5,k2k6,k3k7
#set3->k8,k5,k2,k15,k4k8,k5k9,k6k10,k7k11
#set4->k12,k9,k6,k3,k8k12,k9k13,k10k14,k11k15
#------------------------------------------------------#
print sets_values
#print sets_values[0],sets_values[0].strip('[]'),sets_values[0].strip('[]').split(',')
#print sets_values[0][0]
p_keys=[]

print sets_values
total_sets_solved=[1 for i in sets_values if len(i[0]) ]
print total_sets_solved
if sum(total_sets_solved)!=3:
	print 'NO_KEY_FOUND'
	sys.exit(1)


for set2 in sets_values[0]:
    k=[0]*16
    #k=range(16)
    #print k
    print 's2 ', set2
    print set2.strip('[]').split(',')
    set2=[int(i) for i in set2.strip('[]').split(',')]
    k[4]=set2[0]
    k[1]=set2[1]
    k[14]=set2[2]
    k[11]=set2[3]
    for set3 in sets_values[1]:
        print 's3 ',set3
        set3=[int(i) for i in set3.strip('[]').split(',')]
        k[8]=set3[0];k[5]=set3[1];k[2]=set3[2];k[15 ]=set3[3]   
        for set4 in sets_values[2]:
            print 's4 ', set4
            set4=[int(i) for i in set4.strip('[]').split(',')]
            k[12]=set4[0];k[9]=set4[1];k[6]=set4[2];k[3]=set4[3]
            #print '++++'
            #print k           
            p_keys.append(k[:])
            #for i in p_keys:
            #    print '->', i

print '\n++',real_keys
print 'possible key comb ',len(p_keys)
for ix, itm in enumerate(p_keys[:10]):
    print '+-',itm       
    
print '\n++'     
#------------------------------------------------------#
pool = mp.Pool(processes=8)
results4y = [pool.apply_async(co_solve_equatio_1234_y, args=(key_sets[0][i:i+1],co_cache_access,co_cypter_txt,key_sets,p_keys)) for i in range(16)]# if i%2==0]
output4y = [p.get() for p in results4y]
#------------------------------------------------------#
all_sets=[]
#------------------------------------------------------#
print "======****************=========="       
all_sets=[collect_datas(output4y)]
#-------------------------------------------------------------------------#
print '-----------=-=-=-=-=-===-==', len(all_sets)
#-------------------------------------------------------------------------#
#-----------------Counting-------------------------------#
#all_sets
sets_values=[] #having key values with max counts
sets_max_nmax=[]

eqset1=[[],[],[],[]]
eqset2=[[],[],[],[]]
eqset3=[[],[],[],[]]
eqset4=[[],[],[],[]]

eqsets=[eqset3,eqset3,eqset4,eqset1]
print str(datetime.now())
Final_scored_keys=[]
for values in all_sets:
    (min_enq,key_value_11,dif)=sc.check_scores_4(values,No_of_min_sucess,Total_encrytions,1)
    print min_enq
    print key_value_11
    print dif
    all_diff.append(dif)
    min_req_decrypt.append(min_enq)
    #sets_values.append(set_values)
    sets_values.append([key_value_11])
    #(set_values, sets_max)=count_key_score(values)
    #sets_values.append(set_values)
    #sets_max.append(sets_max)
#------------------------------------------------------#
print str(datetime.now())
Final_result=[]
print sets_values
for i in sets_values[0]:
    Final_result.append( [int(a) for a in i.strip('[]').split(',')])
    print [int(a) for a in i.strip('[]').split(',')]
    
print '--\n'    
#-----------------------------------------------------------------------------------------------#
open(key_stat,'w').write(str( min_req_decrypt)+":"+str(all_diff))
open(key_rst,'w').write(str(max(min_req_decrypt)))


#-----------------------------------------------------------------------------------------------#
print 'F-', Final_result
print 'R+', real_keys
#stat_f=stat_f+[' ',len(Final_result)]
#print stat_f
if len(Final_result)==1:
    print Final_result
    if real_keys==Final_result[0]:
        print real_keys
        print "Match"
        open(key_stat,'w').write(str( min_req_decrypt)+":"+str(all_diff))
        open(key_rst,'w').write(str(max(min_req_decrypt)))
        #stat_f.append("Match")
else:
    open(key_rst,'w').write('0')
    if real_keys in Final_result:
        print "One of ", len(Final_result)
        #stat_f.append("One of %d"%len(Final_result))
    else:
        print "Not Found ", len(Final_result)
        #stat_f.append("Not Found")

#-----------------------------------------------------------------------------------------------#

gc.collect()
pool.close()
pool.join()
del pool
gc.collect()
os.system('sync; echo 3 > /proc/sys/vm/drop_caches')
