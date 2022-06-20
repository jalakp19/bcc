#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define ETH_HLEN 14

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing SIP messages
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/

BPF_HASH(sip_message);
BPF_HASH(counter);

int sip_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;
	
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply


    //check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		goto DROP;
	}

	//shift cursor forward for dynamic ip header size
	void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//We are only listening to port 5060
	if(tcp->dst_port != 5060 && tcp->src_port != 5060) {
		goto DROP;
	}


	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;


	//load first 50 byte of payload into p (payload_array)
	//direct access to skb not allowed
	int p[50];
	u64 i = 0;
	for (i = 0; i < 50; i++) {
		p[i] = load_byte(skb , payload_offset + i);
	}

	u64 ctr=0;
	u64 flag=0;
	u64 ctr_key=0;                      //Stores the length of sip_message data structure
	u64 ctr_subreq_res=1;               //Stores the count of sub request and response i.e Invite,180,200,ack,bye,ack (12)
	u64 *ptr1,*ptr2;
	ptr1 = counter.lookup(&ctr_key);
	ptr2 = counter.lookup(&ctr_subreq_res);
	if (ptr1 != 0) {
		ctr = *ptr1;
	}
	if (ptr2 != 0) {
		flag = *ptr2;
	}

	for(i=0;i<50;i++)
	{
		if(p[i]==13)                    //ASCII code 13 represents carriage return which marks the end of line in sip message
		{
			u64 keyy=ctr;
			u64 valuee=10;              //ASCII code 10 represents new line character
			ctr++;
			sip_message.update(&keyy,&valuee);	

			flag++;
			break;
		}
		u64 keyy=ctr;
		u64 valuee=p[i];
		ctr++;
		sip_message.update(&keyy,&valuee);
	}
	counter.update(&ctr_key,&ctr);
	counter.update(&ctr_subreq_res,&flag);

	if(flag==6)                         // flag==6, if running on ens33. flag==12, if running on lo
	{									//  (Since on lo every message will be printed twice)
		ctr=0;
		flag=0;
		counter.update(&ctr_key,&ctr);
		counter.update(&ctr_subreq_res,&flag);
	}

	//keep the packet and send it to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;
}