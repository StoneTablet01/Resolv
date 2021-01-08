/* WiFi station Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "sti_resolv.h"

/* The examples use WiFi configuration that you can set via project configuration menu
   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

/* tHE HOSTNAME that DNS records are desired for is set in the config file as well
   It can easily be overriden here as well*/

#ifdef CONFIG_FULL_HOSTNAME
#define EXAMPLE_FULL_HOSTNAME      CONFIG_FULL_HOSTNAME
#else
#define EXAMPLE_FULL_HOSTNAME "XMPP.DISMAIL.DE"
#endif

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "wifi station";

static int s_retry_num = 0;

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void sti_cb (char *name, struct ip4_addr *addr){
    static const char *TAG = "sti_cb     ";
    ESP_LOGI(TAG, "...DNS information for %s IP is: "IPSTR"", name, IP2STR(addr));
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // sti Create two pointers that we will use to get information
    // about the connection
    //
    esp_netif_t *esp_netif_handle;
    esp_netif_ip_info_t ap_info;

    esp_netif_handle = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS,
            /* Setting a password implies station will connect to all security modes including WEP/WPA.
             * However these modes are deprecated and not advisable to be used. Incase your Access point
             * doesn't support WPA2, these mode can be enabled by commenting below line */
	     .threshold.authmode = WIFI_AUTH_WPA2_PSK,

            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }


    // Now get information on the ip connection from the netif instance
    // pointed to by esp_netif_handle. I used esp_netif.h to find the
    // calls. I also used the netif test program which is located in the
    // components/esp_netif/test directory to resolve a problem i had with
    // the get_hostname fnction. In any case, First see if netif is up
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".Information on Netif connection");
    if (esp_netif_is_netif_up(esp_netif_handle)){
      ESP_LOGI(TAG, "...Netif is running");
    }
    else {
      ESP_LOGI(TAG, "...Netif is not running");
    }
    // get ip information
    ESP_ERROR_CHECK(esp_netif_get_ip_info(esp_netif_handle, &ap_info));
    ESP_LOGI(TAG, "...Current IP from netif      : "IPSTR"", IP2STR(&ap_info.ip));
    ESP_LOGI(TAG, "...Current netmask from netif : "IPSTR"", IP2STR(&ap_info.netmask));
    ESP_LOGI(TAG, "...Current gateway from netif : "IPSTR"", IP2STR(&ap_info.gw));

    //get hostname information
    const char *hostname = NULL;
    ESP_ERROR_CHECK(esp_netif_get_hostname(esp_netif_handle, &hostname));
    ESP_LOGI(TAG, "...Current Hostname from netif: %s", hostname);

    //get information on the DNS connections

    esp_netif_dns_type_t ask_for_primary = ESP_NETIF_DNS_MAIN;
    esp_netif_dns_type_t ask_for_secondary = ESP_NETIF_DNS_BACKUP;
    esp_netif_dns_type_t ask_for_fallback = ESP_NETIF_DNS_FALLBACK;
    esp_netif_dns_type_t ask_for_dns_max = ESP_NETIF_DNS_MAX;
    esp_netif_dns_info_t dns_info;

    //Get all connections, but save the primary as an ip4_addr
    struct ip4_addr my_server, my_ip;

    esp_netif_get_dns_info(esp_netif_handle, ask_for_primary, &dns_info);
    ESP_LOGI(TAG, "...Name Server Primary (netif): " IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));

    my_server.addr = dns_info.ip.u_addr.ip4.addr;

    esp_netif_get_dns_info(esp_netif_handle, ask_for_secondary, &dns_info);
    ESP_LOGI(TAG, "...Name Server Sec (netif)    : " IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));

    esp_netif_get_dns_info(esp_netif_handle, ask_for_fallback, &dns_info);
    ESP_LOGI(TAG, "...Name Serv Fallback (netif) : " IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));

    esp_netif_get_dns_info(esp_netif_handle, ask_for_dns_max, &dns_info);
    ESP_LOGI(TAG, "...Name Server DNS Max        : " IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));

    err_t ret;
    ip_addr_t *dnsserver_ip_addr_ptr, dnsserver_ip_addr;
    dnsserver_ip_addr_ptr = &dnsserver_ip_addr;
    dnsserver_ip_addr_ptr->type = IPADDR_TYPE_V4;
    dnsserver_ip_addr_ptr->u_addr.ip4.addr = my_server.addr;

    /*
    //examples of using the unified ip_addr_t in printing.
    //first print a ip4_addr, then print the ip_addr_t with . then
    //print using pointer. Note IP2STR expects the address of an ip4_addr struct
    ESP_LOGI(TAG, "Name Server dnsserver_ip_addr: " IPSTR, IP2STR(&my_server));
    ESP_LOGI(TAG, "Name Server dnsserver_ip_addr: " IPSTR, IP2STR(&dnsserver_ip_addr.u_addr.ip4));
    ESP_LOGI(TAG, "Name Server dnsserver_ip_addr: " IPSTR, IP2STR(&dnsserver_ip_addr_ptr->u_addr.ip4));
    */
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".Initialize the Resolver");
    ret = resolv_init(dnsserver_ip_addr_ptr);
    if (ret < 0 ){
      ESP_LOGI(TAG, "... Error initializing resolver " );
    }
    ESP_LOGI(TAG, "...Returned from resolver init");

    //The user can check if the DNS server was configured.
    if (resolv_getserver() != 0){
      my_ip.addr = resolv_getserver();
      ESP_LOGI(TAG, "...DNS server from resolv_getserver is: " IPSTR, IP2STR(&my_ip));
    }
    else{
      ESP_LOGI(TAG, "...DNS server from resolv_getserver not found");
    }

    struct hostent *hp;
    struct ip4_addr *ip4_addr;

    char full_hostname[] = EXAMPLE_FULL_HOSTNAME;


    // The user can check if the name is in the table with resolv_lookup
    // expect dnslookup to be not found as resolv query has not yet been called
    my_ip.addr = resolv_lookup(full_hostname);
    if (resolv_lookup(full_hostname) != 0){
      ESP_LOGI(TAG, "...IP address from resolv_lookup is: " IPSTR, IP2STR(&my_ip));
    }
    else{
      ESP_LOGI(TAG, "...IP address from resolv_lookup not found");
    }




    // experimenting with callbacks
    // first directly call the callback as a typical function
    // Then create a pointer to the user callback function

    //sti_cb is a callback function intended to be called when an ip address
    // is found. it can be called directly from
    // sti_cb(full_hostname, &my_server);

    user_cb_fn sti_cb_ptr = &sti_cb;

    // resolv query creates an entry in a DNS table with the name and callback
    // when the information is found. Resolv_query only enters the information in
    // the table. he table is updated by check entries.
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".Begin Resolv Query");
    resolv_query(full_hostname, sti_cb_ptr);

    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".Begin Check Entries");
    // check if dns table needs update
    check_entries();

    ESP_LOGI(TAG, ".Begin Wait");
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".END Wait");
    ESP_LOGI(TAG, "...Check for ip address from table");

    my_ip.addr = resolv_lookup(full_hostname);
    if (resolv_lookup(full_hostname) != 0){
      ESP_LOGI(TAG, "...IP address from resolv_lookup is: " IPSTR, IP2STR(&my_ip));
    }
    else{
      ESP_LOGI(TAG, "...IP address from resolv_lookup not found");
    }

    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, ".Begin gethostbyname");
    hp = gethostbyname(full_hostname);

    ip4_addr = (struct ip4_addr *)hp->h_addr_list[0];

    ESP_LOGI(TAG, "...Gathering DNS records for %s ", full_hostname);
    ESP_LOGI(TAG, "...Address No. 0 from DNS: " IPSTR, IP2STR(ip4_addr));

    if (hp->h_addr_list[1] != NULL){
      ip4_addr = (struct ip4_addr *)hp->h_addr_list[1];
      ESP_LOGI(TAG, "...Address No. 1 DNS: " IPSTR, IP2STR(ip4_addr));
    }
    else{
      ESP_LOGI(TAG, "...Address No. 1 from DNS was null");
    }

    ESP_LOGI(TAG, "Done with connection... Now shutdown handlers");


    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    vEventGroupDelete(s_wifi_event_group);
}

void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();
}
