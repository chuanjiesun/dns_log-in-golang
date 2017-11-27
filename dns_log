//增加了一个Dot1Q的解析，在vlan里面没有这个老是报错
package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/go-sql-driver/mysql"
	"github.com/astaxie/beego/orm"
)

var (
	devName 	string
	err      	error
	handle   	*pcap.Handle
	InetAddr 	string
	SrcIP    	string
	DstIP    	string
)


//ALTER TABLE `dns_log` CHANGE `id` `id` INT( 11 ) NOT NULL AUTO_INCREMENT 
type Dnslog struct{
	Id 						int 			`orm:"auto"`//`id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY
	Dns_opcode 				string 			`orm:"size(20)"`
	Dns_question_class 		string 			`orm:"size(9)"`
	Dns_question 			string 			`orm:"size(255)"`
	Dns_response_status		string			`orm:"size(255)"`
	Dns_anwsers 			string 			`orm:"size(255)"`
	Dns_type 				string 			`orm:"size(10)"`
	Dns_ttl					uint32 			`orm:"size(32)"`
	Dns_srcip				string 			`orm:"size(255)"`
	Local_dnsserver			string 			`orm:"size(255)"`
	Timestamp 				string 			`orm:"size(255)"`
}

func  get_time() string{
	//写入结果文件
	time_now := string(time.Now().Format("2006-01-02-15-04-05"))
	fmt.Println(time_now)
	return time_now
}



func init_database(){
	db_user := "root"
	db_pass := "root"
	db_ip   := "127.0.0.1"
	db_port := "3306"
	db_name := "dns_sniffer"
	db_source := db_user+":"+db_pass+"@tcp("+db_ip+":"+db_port+")/"+db_name+"?charset=utf8"
	orm.RegisterDriver("mysql", orm.DRMySQL)
	//orm.RegisterDataBase("default", "mysql", "root:root@tcp(127.0.0.1:3306)/scan_test?charset=utf8")
	orm.RegisterDataBase("default", "mysql", db_source)
	//orm.RegisterModelWithPrefix(Get_time()+"_",new(Icsportscan))
	//orm.RegisterModel(new(Dnslog))
	orm.RegisterModelWithSuffix("_"+get_time(),new(Dnslog))
	db, err := orm.GetDB()
	if err != nil {
		log.Fatal(err)
		//os.Exit(1)
	}
	log.Println("db is :",db)
	orm.Debug = true
	orm.RunSyncdb("default",false,true)//创建自动表前缀，需要用这个
}

func main() {
	devName = "eth1"

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload

	init_database()

	// Open device
	handle, err = pcap.OpenLive(devName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter 有可能出现在虚拟机中，出口IP是实际物理机的网关IP，如192.168.1.1，并不是10.0.4.15这样的地址和虚拟网关，所以需要加一个判断
	//var filter string = "udp and port 53 and src host " + InetAddr
	var filter_host string
	var filter string = "udp and port 53"
	fmt.Println("    Filter: ", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		data, cap_info, err := handle.ReadPacketData()//func (h *TPacket) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeEthernet:
				srcmac := eth.SrcMAC.String()
				dstmac :=	eth.DstMAC.String()
				log.Println("srcmac:",srcmac,"dstmac:",dstmac)
			case layers.LayerTypeDot1Q:
				log.Println("vlan capture!")
				log.Println("VLANIdentifier : ",dot1q.VLANIdentifier)
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
				log.Println("SrcIP:",SrcIP,"DstIP:",DstIP)
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			case layers.LayerTypeDNS:
				//dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)
                
				if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
					fmt.Println("------------------------")
					fmt.Println(" DNS Record Detected")

					for _, dnsQuestion := range dns.Questions {
						//t := time.Now()
						//timestamp := t.String()
						//timestamp := t.Format(time.RFC3339)//type -> string
						//timestamp := t.Format("2006-01-02 15:04:05")
						
						fmt.Println(" DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
						fmt.Println(" DNS ResponseCode: ", dns.ResponseCode.String())
						fmt.Println(" DNS # Answers: ", strconv.Itoa(dnsANCount))
						fmt.Println(" DNS Question: ", string(dnsQuestion.Name))
						fmt.Println(" DNS Question Class: ", dnsQuestion.Class.String())
						fmt.Println(" DNS Endpoints: ", SrcIP, DstIP)

						//filter = "udp and port 53 and host "+filter_host
						filter = "udp and port 53 "+filter_host
						//fmt.Println("    Filter: ", filter)
						err = handle.SetBPFFilter(filter)
						if err != nil {
							log.Fatal("setbpffilter error : ",err)
						}

						var DnsAnswer string
						var DnsAnswerTTL uint32
						var dnsAnswerType string
						if dnsANCount > 0 {
							count_1 := 0
							for _, dnsAnswer := range dns.Answers {
								DnsAnswerTTL = dnsAnswer.TTL//uint32
								if dnsAnswer.IP.String() != "<nil>" {
									count_1 += 1
									//log.Println("dnsAnswer.IP : ",dnsAnswer.IP)
									log.Println(" dnsAnswer.TTL : ",dnsAnswer.TTL)
									log.Println(" dnsAnswer.Type :",dnsAnswer.Type.String())
									log.Println(" DNS Answer IP: ", dnsAnswer.IP.String())
									dnsAnswerType = dnsAnswer.Type.String()
									if count_1 == 1{
										DnsAnswer = dnsAnswer.IP.String()
									}else if count_1 > 1{
										DnsAnswer = DnsAnswer+","+dnsAnswer.IP.String()
									}
									
								}
							}
						}
					
						o := orm.NewOrm()
						o.Using("default")//o => type  => *orm.orm
						dns_log := &Dnslog{}

						dns_log.Timestamp = cap_info.Timestamp.String()//timestamp
						dns_log.Dns_opcode = dns.OpCode.String()//dnsOpCode
						//dns_log.Dns_responsecode = dnsResponseCode
						dns_log.Dns_response_status = dns.ResponseCode.String()//dnsResponseCode.String()
						//dns_log.Dns_answer_count = dnsANCount
						dns_log.Dns_question = string(dnsQuestion.Name)
						dns_log.Dns_question_class = dnsQuestion.Class.String()
						dns_log.Dns_anwsers = DnsAnswer
						dns_log.Dns_type = dnsAnswerType
						dns_log.Dns_ttl = DnsAnswerTTL

						dns_log.Dns_srcip = DstIP//这个其实就是DNS响应的结果,所以在插入SQL时需要调换一下
						dns_log.Local_dnsserver = SrcIP
						o.Insert(dns_log)
						//time.Sleep(time.Second * 1)
					}
					fmt.Println("------------------------\n")
				}

			}
		}

		if err != nil {
			fmt.Println("  Error encountered:", err)
		}
	}
}


/*
						// ------------------------
						//     DNS Record Detected
						//     DNS OpCode:  0
						//     DNS ResponseCode:  Non-Existent Domain
						//     DNS # Answers:  0
						//     DNS Question:  _http._tcp.mirrors.tuna.tsinghua.edu.cn
						//     DNS Endpoints:  192.168.1.1 10.0.4.15
						// ------------------------
				
*/
