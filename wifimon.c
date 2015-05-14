/* WIFIMON - wifi monitor, analyzer, utility tool                                               */
/* Authors: Daniele Paolini  -> daniele.paolini@hotmail.it                                      */
/*          Lorenzo Vannucci -> ucci.dibuti@gmail.com                                           */
/*          Marco Venturini  -> alexander00@hotmail.it                                          */
/* To compile: gcc wifimon.c -o wifimon -lpcap -Wall -pedantic                                  */
/* Run as root! Please set your network device in monitor mode!                                 */
/*                                                                                              */
/* This code is distributed under the GPL License. For more info check:                         */
/* http://www.gnu.org/copyleft/gpl.html                                                         */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <netinet/ether.h>
#include <signal.h>
#include <float.h>

#define FILTER "type mgt subtype beacon"      /*beacon frame filter*/

/* TYPE DEFINITIONS */
typedef struct _access_point{
  unsigned char        *mac_address;          /*mac address of the ap*/
  float                ssi_signal_temp_sum,   /*temporary signals sum*/
                       data_rate_temp_sum,    /*temporary rates sum*/
                       data_rate_min,         /*minimum data rate*/
                       data_rate_max,         /*maximum data rate*/
                       data_rate_sum,         /*data rates sum*/
                       ssi_signal_min,        /*minimum ssi signal*/
                       ssi_signal_sum,        /*signals sum*/
                       ssi_signal_max,        /*maximum ssi signal*/
                       tap_counter_temp;
  time_t               data_rate_min_ts,      /*arrival time of minimum data rate*/
                       data_rate_max_ts,      /*arrival time of maximum data rate*/
                       ssi_signal_max_ts,     /*arrival time of maximum ssi signal*/
                       ssi_signal_min_ts;     /*arrival time of minimum ssi signal*/
  int                  tap_counter,           /*tap counter*/
                       channel;               /*channel*/
  struct _access_point *next;                 /*pointer at next element in list*/
} access_point;                               /*stores all info about an access point*/

typedef struct _ssid{
  char*        ssid_name;
  int          num_ap;
  access_point *list_ap;
  struct _ssid *next;                         /*stores all info about a ssid*/
} ssid;

/* GLOBAL VARIABLES */
pcap_t                       *descr;          /*pcap handler descriptor*/
static volatile sig_atomic_t signal_flag;     /*represent incoming SIGINT signal*/
static int                   packet_count;    /*pkt info*/
int                          ssid_len,        /*pkt info*/
                             live,            /*if it's set, live mode will be activated*/
                             json_flag,       /*if it's set, json report will be written*/
                             write_log;       /*if it's set, a log file will be written*/

u_int16_t                    radiotap_len;    /*pkt info*/
int8_t                       ssi_signal;      /*pkt info*/
float                        data_rate;       /*pkt info*/
time_t                       in_time;         /*used for managing timestamp*/
struct tm                    *time_now;       /*used for managing timestamp*/
char                         tmbuf[64],       /*used for managing timestamp*/
                             buf[64];         /*used for managing timestamp*/
FILE                         *out,            /*output file descriptor*/
                             *json;           /*json report file descriptor*/
ssid                         *ssid_list;      /*list of ssid*/

/* FUNCTIONS DEFINITION - see implementation below the main function */
static void          print_usage();
static void          print_help();
static void          packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static void          sigint_handler();
static ssid*         add_ssid(char* name, ssid *list);
static ssid*         search_ssid(char* name, ssid *list);
static access_point* add_ap(unsigned char* mac, access_point* list);
static access_point* search_ap(unsigned char* mac, access_point* list);
static void          update(float signal, float rate, time_t ts, int channel, access_point* ap);
static int           mac_compare(unsigned char* a, unsigned char* b);
static void          print_mac(unsigned char* data, FILE* file_desc);
int                  select_channel(u_int16_t frequency);

/* MAIN FUNCTION */
int main(int argc, char* argv[]){

  int                opt;

  char               *output_file = NULL,
                     *input_file = NULL,
                     *device = NULL;
  char               error_buffer[PCAP_ERRBUF_SIZE];
  const u_char       *packet;

  pcap_if_t          *devpointer = NULL;
  bpf_u_int32        mask;	  	               /*my net mask*/
  bpf_u_int32        net;   		               /*my ip address*/
  struct in_addr     address;
  struct bpf_program compiled_filter;
  struct pcap_pkthdr *header;

  struct sigaction   sigint_action;            /* struct for signal registration */
  sigset_t           new_set,                  /* signal mask */
                     old_set;                  /* signal mask */
  ssid               *ssid_iterator;
  access_point       *ap_iterator;
  struct tm *time_now;
  char tmbuf[64], buf1[64], buf2[64], buf3[64], buf4[64];

  memset(error_buffer, 0, PCAP_ERRBUF_SIZE);

  (void)header; /*get rid of the 'unused variable warning' superfluous in this case*/
  (void)packet; /*get rid of the 'unused variable warning' superfluous in this case*/

  packet_count = 0;
  signal_flag = 0;
  write_log = 0;
  live = 0;
  descr = NULL;
  ssid_list = NULL;

  /* parsing command line */
  while((opt=getopt(argc, argv, "jhl:do:i:")) != -1){
    switch(opt){
      case 'h': /* printing help message */
                print_help(argv[0]);
                return(EXIT_SUCCESS);
                break;
      case 'd': /* printing all availables devices */
                if(pcap_findalldevs(&devpointer, error_buffer) == 0) {
                  int i = 0;
                  fprintf(stdout,"Available devices:\n");
                  while(devpointer) {
                    printf(" %d. %s\n", i++, devpointer->name);
                    devpointer = devpointer->next;
                  }
                }
                fprintf(stdout,"\n\n\n");
                return(EXIT_FAILURE);
      case 'o': /* saving a log file - parameter needed */
                output_file = malloc((strlen(optarg) + 1)*sizeof(*output_file));
                if(output_file== NULL){
                  fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
                  return(EXIT_FAILURE);
                }
                snprintf(output_file,strlen(optarg) + 1,"%s",optarg);
                write_log = 1;
                break;
      case 'i': /* reading an input file - parameter needed */
                input_file = malloc((strlen(optarg) + 1)*sizeof(*input_file));
                if(input_file == NULL){
                  fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
                  return(EXIT_FAILURE);
                }
                snprintf(input_file,strlen(optarg) + 1,"%s",optarg);
                break;
      case 'l': /* reading the device name - parameter needed */
                live = 1;
                device = malloc((strlen(optarg) + 1)*sizeof(*device));
                if(device == NULL){
                  fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
                  return(EXIT_FAILURE);
                }
                snprintf(device,strlen(optarg) + 1,"%s",optarg);
                break;
      case 'j': /* json report */
                json_flag = 1;
                json = fopen("report.json","w");
                break;
      default:  /* wrong option management */
                print_help(argv[0]);
                return(EXIT_FAILURE);
    }
  }

  /* checking parameter */
  if(write_log){
    /* write log file option */
    if(output_file == NULL){
      fprintf(stderr,"ERROR: You must select an output file\n");
      print_help(argv[0]);
      return(EXIT_FAILURE);
    }

    if(access(output_file, F_OK | W_OK | X_OK) == -1){
      fprintf(stderr,"ERROR: You must select a valid output file\n");
      print_help(argv[0]);
      return(EXIT_FAILURE);
    }
    out = fopen(output_file,"w");
  }

  fprintf(stdout,"\nWIFIMON - wifi monitoring tool\n\n");
  fprintf(stdout,"  @  This software will scan the air to monitor all the access points near to you");
  fprintf(stdout," and display relevant info about them.\n");
  fprintf(stdout,"  @  This open source software is released under GPL licence and provided without any warranty.\n");
  fprintf(stdout,"  @  The sniffed packets will not be analyzed to infringe your privacy.\n");
  fprintf(stdout,"  @  Use and modify at your own risk.\n\n\n");

  if(live){

    /* setting signal mask */
    if(sigfillset(&new_set) == -1){
       perror("ERROR: Cannot set signal mask, ");
	     return(EXIT_FAILURE);
    }

    /* masking all signals during SIGINT handler installation */
    if(sigprocmask(SIG_SETMASK, &new_set, &old_set) == -1){
      perror("ERROR: Cannot set process's signal mask, ");
	    return(EXIT_FAILURE);
    }

    /* registering SIGINT handler */
    memset(&sigint_action,'\0',sizeof(sigint_action));
    sigint_action.sa_handler = &sigint_handler;
    sigint_action.sa_flags = SA_RESTART;
    if(sigaction(SIGINT, &sigint_action, NULL) == -1){
      perror("ERROR: Cannot install handler for [SIGINT], ");
      return(EXIT_FAILURE);
    }

    /* unmasking signals */
    if(sigprocmask(SIG_SETMASK, &old_set, NULL) == -1){
      perror("ERROR: Cannot restore process's signal mask, ");
      return(EXIT_FAILURE);
    }

    /* live mode ON */
    fprintf(stdout,"Live capture mode: ON\n");

    /* checking parameter */
    if(device == NULL){
      fprintf(stderr,"ERROR: You must select a device file in order to work offline\n");
      fprintf(stderr,"NOTE: Use -d option as root to see the list of all available devices\n");
      print_usage(argv[0]);
      return(EXIT_FAILURE);
    }

    /* looking up for my netmask and my ip address */
    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
      fprintf(stderr, "ERROR: Can't get netmask for device %s\n", device);
		  net = 0;
		  mask = 0;
      return(EXIT_FAILURE);
	  }

    /* printing info */
    address.s_addr = mask;
    fprintf(stdout,"Monitor Mask: %s\n",inet_ntoa(address));
    address.s_addr = net;
    fprintf(stdout,"Monitor IP: %s\n\n",inet_ntoa(address));

    /* opening device in promiscuos mode with 1 second timeout - BUFSIZ is in pcap.h */
    if((descr = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer)) == NULL){
      fprintf(stderr, "ERROR: %s\n", error_buffer);
      return(EXIT_FAILURE);
    }

    /* setting beacon filter */
    if (pcap_compile(descr, &compiled_filter, FILTER, 1, net) == -1) {
      fprintf(stderr, "ERROR: Couldn't parse filter %s: %s\n", FILTER, pcap_geterr(descr));
      return(EXIT_FAILURE);
    }

    /* applying beacon filter */
    if (pcap_setfilter(descr, &compiled_filter) == -1) {
      fprintf(stderr, "ERROR: Couldn't apply filter %s: %s\n", FILTER, pcap_geterr(descr));
      return(EXIT_FAILURE);
    }

    fprintf(stdout, "Monitoring in progress...\n\n");
    fprintf(stdout, "Press [ctrl+c] or send [SIGINT] to this process [pid:%d] to exit and ",getpid());
    fprintf(stdout,"display statistics\n\n");

    /* pcap loop */
    if (pcap_loop(descr, -1, packet_callback, NULL) == -1){
      fprintf(stderr, "ERROR: Pcap loop error: %s\n", pcap_geterr(descr));
    }

    /* freeing the heap */
    free(device);

  } else{

    /* live mode OFF */
    fprintf(stdout,"Live capture mode: OFF\n");

    /* checking parameter */
    if(input_file == NULL){
      fprintf(stderr,"ERROR: You must select an input file in order to work offline\n");
      print_usage(argv[0]);
      return(EXIT_FAILURE);
    }

    /* opening pcap file */
    if((descr = pcap_open_offline(input_file, error_buffer)) == NULL){
      fprintf(stderr, "ERROR: %s\n", error_buffer);
      return(EXIT_FAILURE);
    }

    /* setting beacon filter */
    if (pcap_compile(descr, &compiled_filter, FILTER, 1, net) == -1) {
      fprintf(stderr, "ERROR: Couldn't parse filter %s: %s\n", FILTER, pcap_geterr(descr));
    return(EXIT_FAILURE);
    }

    /* applying beacon filter */
    if (pcap_setfilter(descr, &compiled_filter) == -1) {
      fprintf(stderr, "ERROR: Couldn't apply filter %s: %s\n", FILTER, pcap_geterr(descr));
    return(EXIT_FAILURE);
    }

    /* reading packets in the pcap file */
    if (pcap_loop(descr, -1, packet_callback, NULL) < 0){
      fprintf(stderr, "ERROR: Pcap loop error: %s\n", pcap_geterr(descr));
    }

    /* freeing the heap */
    free(input_file);

  }

  /*printing final statistics*/
  fprintf(stdout,"\n\nFinal statistics:\n");
  ssid_iterator = ssid_list;
  while(ssid_iterator != NULL){
    fprintf(stdout,"[SSID] name: %s / number of access points: %d\n",ssid_iterator->ssid_name,
                                                                        ssid_iterator->num_ap);

    if(json_flag){
      fprintf(json,"{ \"ssid\": {\n");
      fprintf(json,"    \"name\": \"%s\",\n",ssid_iterator->ssid_name);
      fprintf(json,"    \"number of access point\": \"%d\",\n",ssid_iterator->num_ap);
      fprintf(json,"    \"aplist\": {\n");
      fprintf(json,"    \"ap\": [\n");
    }
    ap_iterator = ssid_iterator->list_ap;
    while(ap_iterator != NULL){
      fprintf(stdout,"  [AP] mac:           ");
      print_mac(ap_iterator->mac_address,stdout);
      fprintf(stdout,"\n");
      fprintf(stdout,"       data rate avg: %f Mbps\n", (float)(ap_iterator->data_rate_sum / (float)ap_iterator->tap_counter));
      fprintf(stdout,"       signal avg:    %f Dbm\n", (float)(ap_iterator->ssi_signal_sum / (float)ap_iterator->tap_counter));
      fprintf(stdout,"       channel:       %d\n",ap_iterator->channel);
      fprintf(stdout,"       max data rate  %f Mbps\n",ap_iterator->data_rate_max);
      time_now = localtime(&ap_iterator->data_rate_max_ts);
      strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", time_now);
      snprintf(buf1, sizeof(buf1), "%s", tmbuf);
      fprintf(stdout,"         at time:     %s\n",buf1);
      fprintf(stdout,"       min data rate  %f Mbps\n",ap_iterator->data_rate_min);
      time_now = localtime(&ap_iterator->data_rate_min_ts);
      strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", time_now);
      snprintf(buf2, sizeof(buf2), "%s", tmbuf);
      fprintf(stdout,"         at time:     %s\n",buf2);
      fprintf(stdout,"       max ssi signal %f Dbm\n",ap_iterator->ssi_signal_max);
      time_now = localtime(&ap_iterator->ssi_signal_max_ts);
      strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", time_now);
      snprintf(buf3, sizeof(buf3), "%s", tmbuf);
      fprintf(stdout,"         at time:     %s\n",buf3);
      fprintf(stdout,"       min ssi signal %f Dbm\n",ap_iterator->ssi_signal_min);
      time_now = localtime(&ap_iterator->ssi_signal_min_ts);
      strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", time_now);
      snprintf(buf4, sizeof(buf4), "%s", tmbuf);
      fprintf(stdout,"         at time:     %s\n",buf4);
      if(json_flag){
        fprintf(json,"          {\"mac\": \"");
        print_mac(ap_iterator->mac_address,json);
        fprintf(json,"\",\n          \"data rate\":\"%f\",\n          \"signal\": \"%f\",\n          \"channel\":\"%d\",\n          \"max data rate\": \"%f\",\n          \"max data rate time\": \"%s\",\n          \"min data rate\": \"%f\",\n          \"min data rate time\": \"%s\",\n          \"max signal\": \"%f\",\n          \"max signal time\": \"%s\",\n          \"min signal\": \"%f\",\n          \"min signal time\": \"%s\"},\n",
                                (float)(ap_iterator->data_rate_temp_sum / (float)ap_iterator->tap_counter_temp),
                                (float)(ap_iterator->ssi_signal_temp_sum / (float)ap_iterator->tap_counter_temp),
                                ap_iterator->channel,
                                ap_iterator->data_rate_max,
                                buf1,
                                ap_iterator->data_rate_min,
                                buf2,
                                ap_iterator->ssi_signal_max,
                                buf3,
                                ap_iterator->ssi_signal_min,
                                buf4
                                );
      }
      ap_iterator = ap_iterator->next;
    }
    fprintf(stdout,"\n");
    if(json_flag)
      fprintf(json,"\b          ]}\n     }\n}\n");
    ssid_iterator = ssid_iterator->next;
  }
  fprintf(stdout,"\n\n");


  /* closing pcap handler descriptor and freeing heap */
  pcap_close(descr);
  if(write_log){
    free(output_file);
    fclose(out);
  }
  if(json_flag)
    fclose(json);
  return(EXIT_SUCCESS);
}

/* FUNCTIONS IMPLEMENTATION */

/* prints usage message*/
static void print_usage(char* s){
  fprintf(stdout,"Usage: %s [OPTIONS] [PARAMETERS]\n",s);
  fprintf(stdout,"NOTE: in order to work properly you must run this program as root and your\nnetwork interface must");
  fprintf(stdout," work in monitor mode.\n");
}


/* prints help message*/
static void print_help(char* s){
  print_usage(s);
  fprintf(stdout,"Option list:\n  -l    live mode:    needs a parameter, capture packets directly from the\n");
  fprintf(stdout,"                      network interface passed as a parameter\n");
  fprintf(stdout,"  -d    device list:  display all network devices availables on this machine\n");
  fprintf(stdout,"                      and exit\n");
  fprintf(stdout,"  -i    input file:   needs a parameter, [mandatory] if live mode is off,\n");
  fprintf(stdout,"                      specifies the file from which to read the packets\n");
  fprintf(stdout,"                      [pcap compatible format is needed]\n");
  fprintf(stdout,"  -o    output file:  needs a parameter, specifies where to save the log file\n");
  fprintf(stdout,"                      of all packets\n");
  fprintf(stdout,"  -j    json report:  prints the report of the monitoring in json format into\n");
  fprintf(stdout,"                      a file named 'report.json'\n");
  fprintf(stdout,"  -h    help:         display this help message\n");
}

/* forces 'packet_callback()' to terminate */
static void sigint_handler(){
  signal_flag = 1;
}

/* manages incoming beacon frames */
static void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

  int x, ssid_len, channel;
  u_int16_t radiotap_len, channel_frequency=0;
  u_int8_t c1=0, c2=0;
  float ssi_signal, data_rate;
  time_t time;
  struct tm *time_now;
  char tmbuf[64], buf[64];
  unsigned char *temp_mac = NULL;
  char* temp_ssid = NULL;
  ssid* temp_ssid_address = NULL, *ssid_iterator = NULL;
  access_point* temp_ap_address = NULL, *ap_iterator = NULL;

  if(signal_flag){
    /* incoming SIGINT, forcing termination */
    pcap_breakloop(descr);
  }

  packet_count ++;

  /*retrieving initial info*/
  time = header->ts.tv_sec;
  time_now = localtime(&time);
  strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", time_now);
  snprintf(buf, sizeof(buf), "%s.%06d", tmbuf, (int) header->ts.tv_usec);
  radiotap_len = (u_int16_t) *(packet + 2);
  temp_mac = malloc((sizeof(unsigned char)*6) + 1);
  if(temp_mac == NULL){
    fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
    exit(EXIT_FAILURE);
  }
  ssid_len = (u_int8_t) packet[radiotap_len + 37];
  temp_ssid = malloc((ssid_len+1)*sizeof(*temp_ssid));
  if(temp_ssid == NULL){
    fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
    exit(EXIT_FAILURE);
  }
  for(x=0;x<ssid_len;x++)
    *(temp_ssid + x) = (char) *(packet + radiotap_len + 38 + x);
  *(temp_ssid + x) = '\0';

  if(write_log){
    /* printing intial info*/
    fprintf(out,"==================================================\n");
    fprintf(out,"Reading packet       %d#\n", packet_count);
    fprintf(out,"Packet size :        %d\n", header->len);
    fprintf(out,"Packet timestamp :   %s\n", buf);
    fprintf(out,"AP SSID:             %s\n",temp_ssid);
  }

  /* retrieving other info */
  switch(radiotap_len){
    case 18 :{
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 18 + 16 + x);
      temp_mac[x] = '\0';
      ssi_signal = (int8_t) *(packet + 14);
      data_rate = (float) *(packet + 9) / 2.0 ;
      c1 = *(packet + 10);
      c2 = *(packet + 11);
      channel_frequency = (c2 << 8) + c1;
      break;
    }
    case 25 :{
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 25 + 16 + x);
      temp_mac[x] = '\0';
      ssi_signal = (int8_t) *(packet + 22);
      data_rate = (float) *(packet + 17) / 2.0 ;
      c1 = *(packet + 18);
      c2 = *(packet + 19);
      channel_frequency = (c2 << 8) + c1;
      break;

    }
    case 26 :{
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 25 + 16 + x);
      temp_mac[x] = '\0';
      ssi_signal = (int8_t) *(packet + 22);
      data_rate = (float) *(packet + 17) / 2.0 ;
      c1 = *(packet + 18);
      c2 = *(packet + 19);
      channel_frequency = (c2 << 8) + c1;
      break;

    }
    case 30 :{
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 25 + 16 + x);
      temp_mac[x] = '\0';
      ssi_signal = (int8_t) *(packet + 22);
      data_rate = (float) *(packet + 17) / 2.0 ;
      c1 = *(packet + 18);
      c2 = *(packet + 19);
      channel_frequency = (c2 << 8) + c1;
      break;

    }
    case 36 :{
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 36 + 16 + x);
      temp_mac[x] = '\0';
      ssi_signal = (int8_t) *(packet + 34);
      data_rate = (float) *(packet + 25) / 2.0 ;
      c1 = *(packet + 26);
      c2 = *(packet + 27);
      channel_frequency = (c2 << 8) + c1;
      break;
    }
    default :{
      fprintf(stdout, "WARNING: This network interface it's not yet supported, results may be incorrect\n");
      for(x=0;x<6;x++)
        temp_mac[x] = (unsigned char) *(packet + 36 + 16 + x);
        temp_mac[x] = '\0';
        ssi_signal = (int8_t) *(packet + 34);
        data_rate = (float) *(packet + 25) / 2.0 ;
        c1 = *(packet + 26);
        c2 = *(packet + 27);
        channel_frequency = (c2 << 8) + c1;
    }
  }

  if(write_log){
    /* printing other info */
    fprintf(out,"AP address :         ");
    print_mac(temp_mac,out);
    fprintf(out,"\n");
    fprintf(out,"SSI signal :         %d Dbm\n", (int) ssi_signal);
    fprintf(out,"Data rate :          %f Mb/s\n", (float) data_rate);
    fprintf(out,"==================================================\n");
  }

  channel = select_channel(channel_frequency);

  temp_ssid_address = search_ssid(temp_ssid, ssid_list);
  if(temp_ssid_address != NULL){
    /* previously stored ssid */
    temp_ap_address = search_ap(temp_mac, temp_ssid_address->list_ap);
    if(temp_ap_address != NULL){
      /* previously stored ap */
      update(ssi_signal, data_rate, time, channel, temp_ap_address);
    } else{
      /* new ap */
      temp_ssid_address->list_ap = add_ap(temp_mac, temp_ssid_address->list_ap);
      update(ssi_signal, data_rate, time, channel, temp_ap_address);
      temp_ssid_address->num_ap ++;
    }
  } else{
    /* new ssid */
    ssid_list = add_ssid(temp_ssid, ssid_list);
    ssid_list->list_ap = add_ap(temp_mac, ssid_list->list_ap);
    ssid_list->num_ap ++;
    update(ssi_signal, data_rate, time, channel, ssid_list->list_ap);
  }

  if(live){
    /* printing temporary statistics every 100 packets */
    ssid_iterator = ssid_list;
    if(packet_count%100 == 0 && ssid_iterator != NULL){
      fprintf(stdout,"Temporary statistics:\n\n");
      while(ssid_iterator != NULL){
        fprintf(stdout,"[SSID] name: %s / number of access points: %d\n",ssid_iterator->ssid_name,
                                                                            ssid_iterator->num_ap);
        ap_iterator = ssid_iterator->list_ap;
        while(ap_iterator != NULL){
          if(ap_iterator->tap_counter_temp > 0){
            /* if tap_counter_temp == 0 we've temporary lost the connection with ap, so not print it */
            fprintf(stdout,"  [AP] mac: ");
            print_mac(ap_iterator->mac_address,stdout);
            fprintf(stdout," / data rate: %f Mbps / signal: %f Dbm / channel: %d\n",
                                      (float)(ap_iterator->data_rate_temp_sum / (float)ap_iterator->tap_counter_temp),
                                      (float)(ap_iterator->ssi_signal_temp_sum / (float)ap_iterator->tap_counter_temp),
                                      channel);
            /* resetting counters */
            ap_iterator->tap_counter_temp= 0;
            ap_iterator->data_rate_temp_sum = 0;
            ap_iterator->ssi_signal_temp_sum = 0;
          }
          ap_iterator = ap_iterator->next;
        }
        fprintf(stdout,"\n");
        ssid_iterator = ssid_iterator->next;
      }
      fprintf(stdout,"\n\n");
    }
  }
}

/* returns the pointer at the structure that contains 'name' if it's in the list, NULL otherwise */
static ssid* search_ssid(char* name, ssid *list){

  ssid* this = list;

  while(this != NULL){
    if(strcmp(this->ssid_name, name) == 0)
      return this;
    this = this->next;
  }
  return NULL;
}

/* returns the new list obtained by adding name on top of the list */
static ssid* add_ssid(char* name, ssid *list){

  ssid *new_ssid = malloc(sizeof(ssid));
  if(new_ssid == NULL){
    fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
    exit(EXIT_FAILURE);
  }

  new_ssid->ssid_name = name;
  new_ssid->list_ap = NULL;
  new_ssid->num_ap = 0;

  new_ssid->next = list;

  return new_ssid;
}

/* returns the pointer at the structure contains 'mac' if it's present in the list, NULL otherwise */
static access_point* search_ap(unsigned char* mac, access_point* list){

  access_point* this = list;

  while(this != NULL){
    if(mac_compare(this->mac_address,mac)==0)
      return this;
    this = this->next;
  }
  return NULL;
}

/* returns the new list obtained by adding 'mac' on top of the list */
static access_point* add_ap(unsigned char* mac, access_point* list){

  access_point *new_ap = malloc(sizeof(access_point));
  if(new_ap == NULL){
    fprintf(stderr,"SEVERE ERROR: memory allocation fail\n");
    exit(EXIT_FAILURE);
  }

  new_ap->mac_address = mac;
  new_ap->ssi_signal_sum = 0;
  new_ap->ssi_signal_temp_sum = 0;
  new_ap->data_rate_temp_sum = 0;
  new_ap->tap_counter_temp = 0;
  new_ap->data_rate_sum = 0;
  new_ap->data_rate_min = FLT_MAX;
  new_ap->data_rate_max = FLT_MIN;
  new_ap->ssi_signal_max = -500.0;
  new_ap->ssi_signal_min = FLT_MAX;
  new_ap->data_rate_min_ts = 0;
  new_ap->data_rate_max_ts = 0;
  new_ap->ssi_signal_max_ts = 0;
  new_ap->ssi_signal_min_ts = 0;
  new_ap->tap_counter = 0;
  new_ap->channel = 0;

  new_ap->next = list;

  return new_ap;
}

/* updates statistics of the ap */
static void update(float signal, float rate, time_t ts, int channel, access_point* ap){
	if(ap != NULL){
		ap->tap_counter ++;
    ap->tap_counter_temp ++;
		ap->ssi_signal_sum += signal;
    ap->ssi_signal_temp_sum += signal;
    ap->data_rate_sum += rate;
    ap->data_rate_temp_sum += rate;
    if(signal < ap->ssi_signal_min){
      ap->ssi_signal_min = signal;
      ap->ssi_signal_min_ts = ts;
    }
    if(signal > ap->ssi_signal_max){
      ap->ssi_signal_max = signal;
      ap->ssi_signal_max_ts = ts;
    }
    if(rate < ap->data_rate_min){
      ap->data_rate_min = rate;
      ap->data_rate_min_ts = ts;
    }
    if(rate > ap->data_rate_max){
      ap->data_rate_max = rate;
      ap->data_rate_max_ts = ts;
    }
    ap->channel = channel;
	}
}

/* compares two mac address */
int mac_compare(unsigned char *a, unsigned char *b){
	int i=0, bol=0;
	while(*(a+i)!='\0' && *(b+i)!='\0' && bol==0){
		if(*(a+i) != *(b+i))
			bol=1;
		i++;
	}
	return bol;
}

/* print mac address on stdout */
void print_mac(unsigned char* data, FILE* file_desc){
	fprintf(file_desc, "%-.2X:%-.2X:%-.2X:%-.2X:%-.2X:%-.2X", data[0], data[1], data[2],	data[3], data[4], data[5]);
}

/* returns correct channel corresponding at 'frequency', 0 if not supported */
int select_channel(u_int16_t frequency){
	switch(frequency){
		case 2412:
			return 1;
		case 2417:
			return 2;
		case 2422:
			return 3;
		case 2427:
			return 4;
		case 2432:
			return 5;
		case 2437:
			return 6;
		case 2442:
			return 7;
		case 2447:
			return 8;
		case 2452:
			return 9;
		case 2457:
			return 10;
		case 2462:
			return 11;
		case 2467:
			return 12;
		case 2472:
			return 13;
		case 2484:
			return 14;
	}
	return 0;
}
