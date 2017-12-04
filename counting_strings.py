import sys


#print_flag=int(sys.argv[3])
input_data=[i.replace('\'','').replace(' [','[') for i in open(sys.argv[1]).read().split(',') if i]
ot_values={}
#print input_data
#for i in input_data:
#	print i
tmp=0
try:
	output_file=open(sys.argv[2],'r')
	for i in output_file.read().split('\n'):
		if i:
			i=[x.replace('\'','').replace(' [','[')  for x in i.split(':')]
			ot_values[i[0]]=int(i[1])
	output_file.close()	
except :
	a=1+1
		
#print input_data
#print ot_values

index=list(set(input_data))
#print index

for i in index:
	try:
		#ot_values[i]:
		ot_values[i]=input_data.count(i)+ot_values[i]
	except KeyError:
		ot_values[i]=input_data.count(i)
	

tmp=sum([ot_values[i] for i in ot_values])
#if print_flag==1:
#	print ot_values
#	no_e_percentage=(float(ot_values[0])/float(tmp))*100.0
#	e_percentage=100.0- no_e_percentage
#	print sys.argv[1],' Total: ',tmp,'Error: %.2f'%e_percentage,'% '#,  ot_values
output_write_data=str(ot_values).strip('{}').replace(',','\n')

open(sys.argv[2],'w').write(output_write_data)
#----------------------------------------------------------------------------------------#


#----------------------------------------------------------------------------------------#
