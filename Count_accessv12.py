#=======================================
#Directly from v10.3_1..not included changed made in v11
#====================================================# 
'''
Script to count the number of cache access by AES (victum) under multithread environment
sample data

30,11,1,Access_Time,[3],44
30,11,1,Access_Time,[6],44
30,11,1,Access_Time,[11],48
30,11,1,Access_Time,[14],44
30,11,1,Access_Time,[16],44
30,11,1,Access_Time,[18],44
30,11,1,Access_Time,[20],44
'''
#===========================================================================================#

import os
import sys
import filter_valid_detection as dt
import count_lines as cl
TABLE_5_START_LINE=64
'''
NO_OF_COMPARE_ELEMENT=int(sys.argv[2] )
try:
	UNIQUENESS=int(sys.argv[3] )
except:	
	UNIQUENESS=0

try:
	EXP_ENCRYPT=int(sys.argv[4] )
except:	
	EXP_ENCRYPT=100

input_file= sys.argv[1] #Sorted_access_time.txt	
file1=open(input_file,'r')	#sample.txt= file containing access data

'''

NO_OF_COMPARE_ELEMENT=int(sys.argv[1] )
try:
	UNIQUENESS=int(sys.argv[2] )
except:	
	UNIQUENESS=0

try:
	EXP_ENCRYPT=int(sys.argv[3] )
except:	
	EXP_ENCRYPT=100

input_file= sys.argv[1] #Sorted_access_time.txt	


#if any run size is more than this value then it is considered that
#this run have traces of 2 encryptions. so encryption will be encryption+1
#This has to be changed for prefetching
RUN_THRESHOLD=70# for prefetching
Last_RUN_THRESHOLD=60 #if the last run has more than this value and t5 item then it will be added to next encryptions as well

Last_RUN_COUNT_THRESHOLD_FOR_NXT=24
MIN_ENCRYPTION_ACCESSES=70 #65
MAX_ENCRYPTION_ACCESSES=250 #not uniqe
total_encrypt_access=0
minimum_encrypt_access=False
#-------------------------------------------------------#
def pure_detect(T1,T2,T3,T4,T5):
	if ((T1==T2==T3==T4==0) and (T5!=0)):
		print '---pure detect-----'
		return True
	else:
		return False
	
#-------------------------------------------------------#
def FindTables(array):
	T1=T2=T3=T4=T5=0
	for item in array:
		if item >=0 and item <16:
			T1=T1+1
		elif item >=16 and item <32 :
			T2=T2+1
		elif item >=32 and item <48:
			T3=T3+1
		elif item >=48 and item <TABLE_5_START_LINE:
			T4=T4+1
		elif item >=TABLE_5_START_LINE:
			T5=T5+1
		
	return T1,T2,T3,T4,T5
#----------------------------------------------------#
if not os.path.isdir('./tmp'):
   os.makedirs('./tmp')
#----------------------------------------------------#   

strip_items=['[',']','\'']

file1=open('Sorted_access_time.txt','r')	#sample.txt= file containing access data


op_file=open('./tmp/Access_count.txt','w')



op_file1=open('./tmp/Cache_lines.txt','w')
if UNIQUENESS==1:
	encry_op=open('./tmp/Encryption_Access_uq.txt','w')
	encry_op1=open('./tmp/First_%d_uq_access.txt'%NO_OF_COMPARE_ELEMENT,'w')
	encry_counts=open('./tmp/First_%d_uq_access_counts.txt'%NO_OF_COMPARE_ELEMENT,'w')
else:
	encry_op=open('./tmp/Encryption_Access.txt','w')
	encry_op1=open('./tmp/First_%d_access.txt'%NO_OF_COMPARE_ELEMENT,'w')
	encry_counts=open('./tmp/First_%d_access_counts.txt'%NO_OF_COMPARE_ELEMENT,'w')

hist_data=open('./tmp/hist_data.txt','w')
spike_info=open('./tmp/spike.txt','w')
file_check=open('./tmp/file_checker.txt','w')
all_spike_counts=open('./stat1/all_spike_linesize.txt','a')
all_en_len=open('./stat1/all_en_len.txt','a')
all_en_len_uq=open('./stat1/all_en_len_uq.txt','a')
match_en_len=open('./stat1/last_r_match_en_len.txt','a')
unmatch_en_len=open('./stat1/last_r_umatch_en_len.txt','a')

all_en_len_ls=[]
all_en_len_uq_ls=[]
first_n_access=[]
line1=file1.readline()
reference=line1.split(',')[:-1]
prev=0
prev_count=0
count=1
sum_=0
encry_count=1
table5_flag=0
thread_count=1
encrypt_flag=0
per_encryption=[]
prev_T5_value=0
temp=1
cache_lines=[]
reched_count_flag= True
unexpected_flag=False
compare_count=0
actual_end_encrypt_no=[]
actual_end_encrypt_clen=[]
first_n_count=[]
detected_encrypt_no=[]

all_count_data=[]
spike_info_flag=0
pre_encrypt_no=0 

pre_thread_id=0
curr_thread_id=0
skip_thread_flag=0
thread_id_count=0;
line_counts=[]
T5_values=[]
en_detect_place=[]
en_last_run_stat=[]
cache_line_count=0
pure_detect_clines=[]
first_n_count_clines=[]
pure_end_encryption=False
first_n_T5_encryption=False
init_T5_counts=[]
all_init_T5_counts=[]
just_done_encrypt=False
#------------------------------------------------------------------------------------------_#

def write_first_n_access(encryp,values):
	print '---first---', encryp
	unq_count=len(set(values))
	'''
	if unq_count<55 and unq_count< 2*NO_OF_COMPARE_ELEMENT:
		first_n_count.append(encryp)
		encry_op1.write("Encryption "+str(encryp)+" : "+ str(values)+"\n")
	else:
		print 'NOT qualified for First n',unq_count	
	'''
	first_n_count.append(encryp)
	encry_op1.write("Encryption "+str(encryp)+" : "+ str(values)+"\n")
	line_counts_tmp=[t - s for s, t in zip(values, values[1:])]
	line_count=sum(1 for number in line_counts_tmp if number < 0)+1
	line_counts.append(line_count)
	print line_count
#------------------------------------------------------------------------------------------_#
T5_count=0
AT_least_1_No_T5=True
Prev_row=[]
cache_lines.append(int(line1.split(",")[-1].strip("\n")))
for line in file1:	
	if(reference[-1]==line.split(',')[:-1][-1] and reference[-2]!=line.split(',')[:-1][-2]):
		thread_count=thread_count+1
			
	elif(reference[-1]!=line.split(',')[:-1][-1]):
		#op_file1.write(reference[0].strip("'")+", "+reference[-1].strip("'")+", "+str(thread_count)+"\n")
		#op_file1.write("\n")
		sum_=sum_+thread_count
		thread_count=1
	
	if(reference==line.split(',')[:-1]):
		count=count+1
		value=int(line.split(",")[-1].strip("\n"))
		cache_lines.append(value)
		
	#After every seperate value	
	else:
		(T1,T2,T3,T4,T5)=FindTables(cache_lines)
		# Ignore one T5 entry
		if(T5==1 and not just_done_encrypt):
			print'T5 value is 1'
			T5=0
			count=count-1
			res='%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \n' %( reference[0],reference[1],reference[2],str(count),str(T1),str(T2),str(T3),str(T4),str(T5))
			cache_lines=[item for item in cache_lines if item<TABLE_5_START_LINE]
		else:
			res='%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \n' %( reference[0],reference[1],reference[2],str(count),str(T1),str(T2),str(T3),str(T4),str(T5))
		#--------------------#
		all_count_data.append(count)
		hist_data.write(str(count)+",")
		#--------------------#
		
		T5_values.append(T5)
		en_detect_place.append(0)
		if (sum([T1,T2,T3,T4,T5])==0):
			T5_values[-1]=1
		#--------------------#		
		### Find if there is any spike
		curr_encrypt_no=int(reference[2])
		
		if(curr_encrypt_no-pre_encrypt_no >1):
			spike_info_flag=1
			spike_info.write("Spike ,"+str(pre_encrypt_no)+"," +str(curr_encrypt_no)+"\n")
			all_spike_counts.write(str(count)+',')
			
		pre_encrypt_no=curr_encrypt_no
		
		
		### Find if V is scheduled between all consecutive thread id
		if(thread_id_count ==0):
			pre_thread_id=int(reference[1])
			
		curr_thread_id=int(reference[1])
		
		if(curr_thread_id-pre_thread_id > 1):
			spike_info.write(" V is not scheduled between "+str(pre_thread_id) +","+ str(curr_thread_id-1)+"\n")
		
		pre_thread_id=curr_thread_id
		thread_id_count=thread_id_count+1
		
		#---------------------------------------------------------------------------------#		
		if (T5) or (sum([T1,T2,T3,T4,T5])==0):
			T5_count=T5_count+1
			init_T5_counts.append(count)

		if (T5_count>1 and prev_T5_value and not T5 and Prev_not_null):
 
			T5_count=0

		if (not T5):
 			AT_least_1_No_T5=True
			just_done_encrypt=False
			T5_count=0
#		#print 'Current total', et1

		#---------------------------------------------------------------------------------#
		print cache_line_count,res
		cache_line_count=cache_line_count+1
		#---------------------------------------------------------------------------------#		
		
		#First N access
		if  compare_count >= NO_OF_COMPARE_ELEMENT and reched_count_flag :
			#print "cout++: ",compare_count
			#print len(per_encryption),per_encryption
			first_n_access=per_encryption[:]
			first_n_count_clines.append(cache_line_count)
			print '+++First n access+++',
			reched_count_flag= False			
			print 'DET:',encry_count, 'AC:',len(first_n_access), 'UAC',len(set(first_n_access))

			
		#---------------------------------------------------------------------------------#
		#pure Detect and end of encryption and it shoud apeared atleast 1 run before pure
		if first_n_access and pure_detect(T1,T2,T3,T4,T5) and cache_line_count>first_n_count_clines[-1]+1:
			pure_end_encryption=True
			print 'pure_end_encryption=True'
		#---------------------------------------------------------------------------------#	
		#---------------------------------------------------------------------------------#
		#first_n_access and 2 times T5 deteched
		#if first_n_access and prev_T5_value and T5 and AT_least_1_No_T5:
		#	first_n_T5_encryption=True #<-------
		#	print 'first_n_T5_encryption=True',prev_T5_value
		#---------------------------------------------------------------------------------#
		#print "cout: ",compare_count	
		#---total_encrypt_access=total_encrypt_access+count
		op_file.write(res) 
		
		#print cache_lines
		op_file1.write(" Cache Lines  "+ str(len(cache_lines))+" " +str(cache_lines)+"\n")
		
		
		#if (prev_T5_value and count>RUN_THRESHOLD):
		if (prev_T5_value and (count>RUN_THRESHOLD or count>Last_RUN_THRESHOLD )):
			if count>RUN_THRESHOLD:
				print 'prev_T5_value and count>RUN_THRESHOLD'
			if count>Last_RUN_THRESHOLD:
				print 'count>Last_RUN_THRESHOLD'
		        unexpected_flag=True
		        
		        
		if (total_encrypt_access > MIN_ENCRYPTION_ACCESSES):
			minimum_encrypt_access=True  
			print '----+----', total_encrypt_access  
			       
		#code for per encryption lookup
		if(not T5 ):
			per_encryption.extend(cache_lines)
			total_encrypt_access=total_encrypt_access+count
			
		elif((not prev_T5_value and minimum_encrypt_access==True) or unexpected_flag==True or pure_end_encryption==True) or (first_n_T5_encryption==True):
			per_encryption.extend([item for item in cache_lines if item<TABLE_5_START_LINE])
			print_values=per_encryption
			#print_values.sort()
			encry_op.write("Encryption "+str(encry_count)+" : "+ str(len(print_values))+" :"+str(print_values)+"\n") 
			en_detect_place[-1]=1
			detected_encrypt_no.append(encry_count)
			all_en_len_ls.append(len(per_encryption))
			all_en_len_uq_ls.append(len(set(per_encryption)))
			pure_end_encryption=False
			just_done_encrypt=True
			#----------------------------------------------------------------------------------------#
			print " End of Encryption ", encry_count, len(print_values)
			if first_n_access:
			    write_first_n_access(encry_count,first_n_access)
			#----------------------------------------------------------------------------------------#
			all_init_T5_counts.append(init_T5_counts[:-1])
			if sum(init_T5_counts[:-1])>MIN_ENCRYPTION_ACCESSES:
				encry_count=encry_count+1
				print '---Total_T5_counts exist MIN_ENCRYPTION_ACCESSES-----'
				print '----Encrypt=Encrypt+1-----'
			init_T5_counts=[]
					
			#----------------------------------------------------------------------------------------#
			actual_end_encrypt_clen.append(all_count_data[-1])
			actual_end_encrypt_no.append(int(reference[2]))
			
						    
		        #----------------------------------------------------------------------------------------#
			
			AT_least_1_No_T5=False
			    		
			per_encryption=[]
			first_n_access=[]
			total_encrypt_access=0
			#----------------------------------------------------------------------------------------#
			if first_n_T5_encryption==True:
				per_encryption.extend([item for item in cache_lines if item<TABLE_5_START_LINE])
				first_n_T5_encryption=False
				
			if (count>Last_RUN_COUNT_THRESHOLD_FOR_NXT):   #-<--------------------------
				per_encryption.extend([item for item in cache_lines if item<TABLE_5_START_LINE])				
				total_encrypt_access=count
			
			
			#----------------------------------------------------------------------------------------#
			#if line size is more than RUN_THRESHOLD, we considered that it has 2 encryptions
			if count>RUN_THRESHOLD and unexpected_flag==False:
			    print '++++++'
			    encry_count=encry_count+2
			elif count>Last_RUN_THRESHOLD :
			    print "count>Last_RUN_THRESHOLD"
			    en_last_run_stat.append([cache_line_count,encry_count])
			    per_encryption.extend([item for item in cache_lines if item<TABLE_5_START_LINE])
			    encry_count=encry_count+1		
			    total_encrypt_access=count		
			else:
			    encry_count=encry_count+1
			#----------------------------------------------------------------------------------------#
			print "-----------------------+---------------------------"    
			print "Next Encryption ", encry_count
			
			minimum_encrypt_access=False
			table5_flag=1
			compare_count=0
			unexpected_flag=False
			#print encry_count

			print "-----------------------+---------------------------"
			reched_count_flag= True
		else:
			per_encryption.extend([item for item in cache_lines if item<TABLE_5_START_LINE])
			total_encrypt_access=total_encrypt_access+count
			if pure_detect(T1,T2,T3,T4,T5) or (sum([T1,T2,T3,T4,T5])==0):
				per_encryption=[]
				init_T5_counts=[]
				total_encrypt_acces=0
				pure_detect_clines.append(cache_line_count)
			table5_flag=0
			print "---"

		#-------------------------------------------------------------------#

		if UNIQUENESS==1:
			compare_count=len(set(per_encryption))
		else:
			compare_count=len(per_encryption)			
		print compare_count
		#-------------------------------------------------------------------#			
		
		prev=reference[0]
		prev_count=prev_count+1
		prev_T5_value=T5

		
		reference=line.split(',')[:-1]
		count=1
		cache_lines=[]
		cache_lines.append(int(line.split(",")[-1].strip("\n")))
		Prev_not_null=0
		Prev_row=[T1,T2,T3,T4,T5]
		if(Prev_row[0] or Prev_row[1] or Prev_row[2] or Prev_row[3]):
			Prev_not_null=1

if minimum_encrypt_access==True:
	print '---End of Cache lines-----'
	#encry_op.write("Encryption "+str(encry_count)+" : "+ str(len(print_values))+" :"+str(print_values)+"\n") 
	encry_op.write("Encryption "+str(encry_count)+" : "+ str(len(per_encryption))+" :"+str(per_encryption)+"\n") 
	print " End of Encryption ", encry_count
	en_detect_place[-1]=1
	detected_encrypt_no.append(encry_count)	
	T5_values[-1]=99 #to indicate end of cache lines
	
	if first_n_access:
	    write_first_n_access(encry_count,first_n_access)
	    actual_end_encrypt_clen.append(all_count_data[-1])
	    actual_end_encrypt_no.append(int(reference[2]))	
	    #print '=>',actual_end_encrypt_no
	print "write Last run "
	#actual_end_encrypt_no=int(reference[2])	
	#print '=',actual_end_encrypt_no
	print line 
	
	detected_sofar_encrypt_no=encry_count




(T1,T2,T3,T4,T5)=FindTables(cache_lines)
res='%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \t%3s \n' %( reference[0],reference[1],reference[2],str(count),str(T1),str(T2),str(T3),str(T4),str(T5))	
curr_encrypt_no=int(reference[2])
all_count_data.append(count)	
if(curr_encrypt_no-pre_encrypt_no >1):
	spike_info_flag=1
	spike_info.write("Spike ,"+str(pre_encrypt_no)+"," +str(curr_encrypt_no)+"\n")


if(spike_info_flag==0):	
	spike_info.write("No Spike \n")
	all_en_len_uq.write(str(all_en_len_uq_ls).strip('[]')+',')	
	all_en_len.write(str(all_en_len_ls).strip('[]')+',')	
	all_en_len_uq.close()
	all_en_len.close()
	
op_file.write(res) 		
op_file1.write("Total="+str(sum_))
encry_counts.write(str(line_counts).strip('[]'))
encry_counts.close()
encry_op.close()
op_file.close()
op_file1.close()
hist_data.close()
spike_info.close()
all_spike_counts.close()
#all_count_data.sort()
#print all_count_data[-1]
file_check.write('%d' % all_count_data[-1])

#print all_count_data
file_check.close()
#----------------------------------------------------------------------#
#print T5_values
#print en_detect_place

valid_till_en=dt.min_valid_dettions(T5_values,en_detect_place,en_last_run_stat)
(match,unmatch)=dt.check_last_run_inclusion(T5_values,en_detect_place,actual_end_encrypt_no,actual_end_encrypt_clen)

if match:
	match_en_len.write(str(match).strip('[]')+',')
if unmatch:
	unmatch_en_len.write(str(match).strip('[]')+',')	
unmatch_en_len.close()
match_en_len.close()
#----------------------------------------------------------------------#
unexp_run=[ix for ix, i in enumerate(all_count_data) if i>=Last_RUN_THRESHOLD]
#print len(all_count_data),all_count_data

print unexp_run
least_valid_en=-1
indexes=[ix for ix, i in enumerate(en_detect_place)if i==1]
if unexp_run:
	start=0
	for ix,i in enumerate(indexes):
		if unexp_run[0] in range(start,i):
			least_valid_en=ix
			break
		else:
			start=ix
	print '+++All Run Except found at+++',least_valid_en
#----------------------------------------------------------------------#
print '---------'
print len(actual_end_encrypt_clen),actual_end_encrypt_clen
print len(actual_end_encrypt_no),actual_end_encrypt_no
print '---------'
print set(range(EXP_ENCRYPT+1)[1:])^set(first_n_count)

print 'unexpected_last_run',en_last_run_stat
print 'first_n_count', first_n_count
print 'Detected',detected_encrypt_no
print '\n'
#print all_init_T5_counts
#----------------------------------------------------------------------#
final_encrypt=0
#------------------------Calculating Results---------------------------#
if en_last_run_stat:
	value=en_last_run_stat[0][1]
	if valid_till_en>value:
		final_encrypt= value
	else:
		final_encrypt=valid_till_en-1
else:
	final_encrypt=valid_till_en		

if least_valid_en!=-1:
	if least_valid_en<final_encrypt:
		final_encrypt=	least_valid_en

open('stat1/our_result.txt','a').write(str(final_encrypt)+',')
print '=*===>',final_encrypt,'\n'
#----------------------------------------------------------------------#


#if actual_end_encrypt_no!=(detected_sofar_encrypt_no-1):
if (first_n_count==range(EXP_ENCRYPT+1)[1:]):
	print 0
else:
	print 1
if en_last_run_stat:
	print '\n2'	
