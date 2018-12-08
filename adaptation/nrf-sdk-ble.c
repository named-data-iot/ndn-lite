
#include "nrf-sdk-ble.h"

// forward declaring some functions
int advertising_init(const uint8_t *payload, uint32_t payload_len);

// keeps track of how many advertisements have been sent for the last call to
// nrf_sdk_ble_adv_start
int m_current_adv_count = 0;

// pointer to callback function that was passed into nrf_sdk_ble_scan_start
void (*m_scan_callback)(const uint8_t *scan_data, uint8_t scan_data_len);


/**@brief Function for handling asserts in the SoftDevice.
 *
 * @details This function is called in case of an assert in the SoftDevice.
 *
 * @warning This handler is an example only and is not meant for the final product. You need to analyze
 *          how your product is supposed to react in case of assert.
 * @warning On assert from the SoftDevice, the system can only recover on reset.
 *
 * @param[in] line_num     Line number of the failing assert call.
 * @param[in] p_file_name  File name of the failing assert call.
 */
void assert_nrf_callback(uint16_t line_num, const uint8_t * p_file_name)
{
    app_error_handler(0xDEADBEEF, line_num, p_file_name);
}

/**@brief Function for initializing the scanning.
 */
static int scan_start(void)
{
    ret_code_t err_code;

    err_code = nrf_ble_scan_start(&m_scan);
    if (err_code != NRF_SUCCESS) {
      printf("in scan_start, nrf_ble_scan_start failed\n");
      return NRF_BLE_OP_FAILURE;
    }

    return NRF_BLE_OP_SUCCESS;
}

static void scan_evt_handler(scan_evt_t const * p_scan_evt)
{
  switch (p_scan_evt->scan_evt_id) {
  case NRF_BLE_SCAN_EVT_SCAN_TIMEOUT: {
    printf("Scan timed out.\n");
    scan_start();
  } break;
  case NRF_BLE_SCAN_EVT_FILTER_MATCH: {
    printf("Got a filter match!\n");

    const ble_gap_evt_adv_report_t *p_adv_report = p_scan_evt->params.filter_match.p_adv_report;

    m_scan_callback(p_adv_report->data.p_data, p_adv_report->data.len);

  }

  default:
    break;
  }
}


/**@brief Function for initialization the scanning and setting the filters.
 */
static int scan_init(void)
{
    ret_code_t          err_code;
    nrf_ble_scan_init_t init_scan;

    memset(&init_scan, 0, sizeof(init_scan));

    init_scan.connect_if_match = false;
    init_scan.conn_cfg_tag = APP_BLE_CONN_CFG_TAG;
    init_scan.p_scan_param = &m_scan_param;

    err_code = nrf_ble_scan_init(&m_scan, &init_scan, scan_evt_handler);
    if (err_code != NRF_SUCCESS) {
      printf("in scan_init, nrf_ble_scan_init failed\n");
      return NRF_BLE_OP_FAILURE;
    }

    err_code = nrf_ble_scan_filter_set(&m_scan, 
                                       SCAN_UUID_FILTER, 
                                       &m_adv_uuids[HART_RATE_SERVICE_UUID_IDX]);
    if (err_code != NRF_SUCCESS) {
      printf("in scan_init, nrf_ble_scan_filter_set failed\n");
      return NRF_BLE_OP_FAILURE;
    }

    err_code = nrf_ble_scan_filter_set(&m_scan, 
                                       SCAN_UUID_FILTER, 
                                       &m_adv_uuids[RSCS_SERVICE_UUID_IDX]);
    if (err_code != NRF_SUCCESS) {
      printf("in scan_init, nrf_ble_scan_filter_set failed\n");
      return NRF_BLE_OP_FAILURE;
    }

    err_code = nrf_ble_scan_filters_enable(&m_scan, 
                                           NRF_BLE_SCAN_ALL_FILTER, 
                                           false);
    if (err_code != NRF_SUCCESS) {
      printf("in scan_init, nrf_ble_scan_filters_enable failed\n");
      return NRF_BLE_OP_FAILURE;
    }

    return NRF_BLE_OP_SUCCESS;

}

/**@brief Function for checking if an advertising module configuration is legal.
 *
 * @details Advertising module can not be initialized if high duty directed advertising is used
 *          together with extended advertising.
 *
 * @param[in] p_config Pointer to the configuration.
 *
 * @return True  If the configuration is valid.
 * @return False If the configuration is invalid.
 */
static bool config_is_valid_custom(ble_adv_modes_config_t const * const p_config)
{
    if ((p_config->ble_adv_directed_high_duty_enabled == true) &&
        (p_config->ble_adv_extended_enabled == true))
    {
        return false;
    }
#if !defined (S140)
    else if ( p_config->ble_adv_primary_phy == BLE_GAP_PHY_CODED ||
              p_config->ble_adv_secondary_phy == BLE_GAP_PHY_CODED)
    {
        return false;
    }
#endif // !defined (S140)
    else
    {
        return true;
    }
}

uint32_t ble_advertising_init_custom(ble_advertising_t            * const p_advertising,
                              ble_advertising_init_t const * const p_init)
{
    uint32_t ret;
    if ((p_init == NULL) || (p_advertising == NULL))
    {
        return NRF_ERROR_NULL;
    }
    if (!config_is_valid_custom(&p_init->config))
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    p_advertising->adv_mode_current               = BLE_ADV_MODE_IDLE;
    p_advertising->adv_modes_config               = p_init->config;
    p_advertising->conn_cfg_tag                   = BLE_CONN_CFG_TAG_DEFAULT;
    p_advertising->evt_handler                    = p_init->evt_handler;
    p_advertising->error_handler                  = p_init->error_handler;
    p_advertising->current_slave_link_conn_handle = BLE_CONN_HANDLE_INVALID;
    p_advertising->p_adv_data                     = &p_advertising->adv_data;

    memset(&p_advertising->peer_address, 0, sizeof(p_advertising->peer_address));

    // Copy advertising data.
    if (!p_advertising->initialized)
    {
        p_advertising->adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
    }
    p_advertising->adv_data.adv_data.p_data = p_advertising->enc_advdata;

    if (p_advertising->adv_modes_config.ble_adv_extended_enabled == true)
    {
#ifdef BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
        p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED;
#else
    p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
#endif // BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
    }
    else
    {
        p_advertising->adv_data.adv_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
    }

    ret = ble_advdata_encode(&p_init->advdata, p_advertising->enc_advdata, &p_advertising->adv_data.adv_data.len);
    VERIFY_SUCCESS(ret);

    if (&p_init->srdata != NULL)
    {
        p_advertising->adv_data.scan_rsp_data.p_data = p_advertising->enc_scan_rsp_data;
        if (p_advertising->adv_modes_config.ble_adv_extended_enabled == true)
        {
#ifdef BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
            p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED;
#else
            p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
#endif // BLE_GAP_ADV_SET_DATA_SIZE_EXTENDED_CONNECTABLE_MAX_SUPPORTED
        }
        else
        {
            p_advertising->adv_data.scan_rsp_data.len = BLE_GAP_ADV_SET_DATA_SIZE_MAX;
        }
        ret = ble_advdata_encode(&p_init->srdata,
                                  p_advertising->adv_data.scan_rsp_data.p_data,
                                 &p_advertising->adv_data.scan_rsp_data.len);
        VERIFY_SUCCESS(ret);
    }
    else
    {
        p_advertising->adv_data.scan_rsp_data.p_data = NULL;
        p_advertising->adv_data.scan_rsp_data.len    = 0;
    }

    // Configure a initial advertising configuration. The advertising data and and advertising
    // parameters will be changed later when we call @ref ble_advertising_start, but must be set
    // to legal values here to define an advertising handle.
    p_advertising->adv_params.primary_phy     = BLE_GAP_PHY_1MBPS;
    p_advertising->adv_params.duration        = p_advertising->adv_modes_config.ble_adv_fast_timeout;
    p_advertising->adv_params.properties.type = BLE_GAP_ADV_TYPE_NONCONNECTABLE_SCANNABLE_UNDIRECTED;
    p_advertising->adv_params.p_peer_addr     = NULL;
    p_advertising->adv_params.filter_policy   = BLE_GAP_ADV_FP_ANY;
    p_advertising->adv_params.interval        = p_advertising->adv_modes_config.ble_adv_fast_interval;

    ret = sd_ble_gap_adv_set_configure(&p_advertising->adv_handle, NULL, &p_advertising->adv_params);
    VERIFY_SUCCESS(ret);

    p_advertising->initialized = true;
    return ret;
}

/**@brief Function for stopping advertising.
 */
int nrf_sdk_ble_adv_stop()
{

    // stop any advertising that was already happening

    printf("nrf_sdk_ble_adv_stop was called.\n");

    ret_code_t ret = sd_ble_gap_adv_stop(m_advertising.adv_handle);
    switch (ret) {
      case NRF_SUCCESS: {
        printf("sd_ble_gap_adv_stop returned NRF_SUCCESS\n");
        break;
      }
      case NRF_ERROR_INVALID_STATE: {
        printf("sd_ble_gap_adv_stop returned NRF_ERROR_INVALID_STATE\n");
        break;
      }
      case BLE_ERROR_INVALID_ADV_HANDLE: {
        printf("sd_ble_gap_adv_stop returned BLE_ERROR_INVALID_ADV_HANDLE\n");
        break;
      }
      default: {
        printf("sd_ble_gap_adv_stop returned unexpected: %d\n", ret);
        break;
      }
    }

    // it is okay if the return value is NRF_ERROR_INVALID_STATE, that means we weren't advertising
    if (ret != NRF_SUCCESS && ret != NRF_ERROR_INVALID_STATE) {
      printf("in nrf_sdk_ble_adv_stop, return of sd_ble_gap_adv_stop was not NRF_SUCCESS or NRF_ERROR_INVALID_STATE\n");
      return NRF_BLE_OP_FAILURE;
    }

    m_current_adv_count = 0;

    return NRF_BLE_OP_SUCCESS;
}

/**@brief Function for initializing the advertising and the scanning.
 */
int nrf_sdk_ble_adv_start(const uint8_t *payload, uint32_t payload_len)
{

    ret_code_t err_code;

    // stop any advertising that was already happening
    if (nrf_sdk_ble_adv_stop() != NRF_BLE_OP_SUCCESS) {
      printf("in nrf_sdk_ble_adv_start, nrf_sdk_ble_adv_stop failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    if (advertising_init(payload, payload_len) != NRF_BLE_OP_SUCCESS) {
      printf("in nrf_sdk_ble_adv_start, advertising_init failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    //check if there are no flash operations in progress
    if (!nrf_fstorage_is_busy(NULL))
    {
        // Start advertising.
        err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
        if (err_code != NRF_SUCCESS) {
          printf("in nrf_sdk_ble_adv_start, ble_advertising_start failed.\n");
          return NRF_BLE_OP_FAILURE;
        }
    }

    return NRF_BLE_OP_SUCCESS;
}

/**@brief Function for handling advertising events.
 *
 * @param[in] ble_adv_evt  Advertising event.
 */
static void on_adv_evt(ble_adv_evt_t ble_adv_evt)
{
    switch (ble_adv_evt)
    {
        case BLE_ADV_EVT_FAST:
        {
          printf("Started ble advertising.\n");
          m_current_adv_count++;
          printf("Current adv count: %d\n", m_current_adv_count);
          if (m_current_adv_count > NRF_BLE_EXT_ADV_BURST_NUM) {
            printf("in on_adv_evt, m_current_adv_count exceeded NRF_BLE_EXT_ADV_BURST_NUM, stopping advertisement.\n");
            nrf_sdk_ble_adv_stop();
          }
        } break;

        case BLE_ADV_EVT_IDLE:
        {
            ret_code_t err_code = ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST);
            if (err_code != NRF_SUCCESS)
              printf("in on_adv_evt, ble_advertising_start failed.\n");
        } break;

        default:
            // No implementation needed.
            break;
    }
}

/**@brief Function for initializing the advertising functionality.
 */
int advertising_init(const uint8_t *payload, uint32_t payload_len)
{

    if (payload_len > NRF_BLE_EXT_ADV_MAX_PAYLOAD) {
      printf("advertising_init failed; payload_len was larger than NRF_BLE_EXT_ADV_MAX_PAYLOAD\n");
      return NRF_BLE_OP_FAILURE;
    }

    ret_code_t             err_code;
    ble_advertising_init_t init;

    memset(&init, 0, sizeof(init));

    init.advdata.include_ble_device_addr = true;
    init.advdata.name_type               = BLE_ADVDATA_NO_NAME;
    init.advdata.include_appearance      = false;
    init.advdata.flags                   = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    init.advdata.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    init.advdata.uuids_complete.p_uuids  = m_adv_uuids;

    ble_advdata_manuf_data_t                  manuf_data; // Variable to hold manufacturer specific data
    manuf_data.company_identifier             =  0xFFFF; // Filler company ID
    manuf_data.data.p_data                    = payload;
    manuf_data.data.size                      = payload_len;
    init.advdata.p_manuf_specific_data        = &manuf_data;

    printf("Size of manufacturer specific data: %d", manuf_data.data.size);
    
    init.config.ble_adv_extended_enabled = true;
    init.config.ble_adv_fast_enabled  = true;
    init.config.ble_adv_fast_interval = APP_ADV_INTERVAL;
    init.config.ble_adv_fast_timeout  = APP_ADV_DURATION;

    init.evt_handler = on_adv_evt;

    err_code = ble_advertising_init_custom(&m_advertising, &init);
    if (err_code != NRF_SUCCESS) {
      printf("in advertising_init, ble_advertising_init_custom_failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    ble_advertising_conn_cfg_tag_set(&m_advertising, APP_BLE_CONN_CFG_TAG);

    return NRF_BLE_OP_SUCCESS;
}

/**@brief Function for starting scanning.
*/
int nrf_sdk_ble_scan_start(void (*scan_callback)(const uint8_t *scan_data, uint8_t scan_data_len)) {

    m_scan_callback = scan_callback;

    //check if there are no flash operations in progress
    if (!nrf_fstorage_is_busy(NULL))
    {
        // Start scanning for advertisements from other ndn-lite ble faces
        if (scan_start() != NRF_BLE_OP_SUCCESS) {
          printf("in nrf_sdk_ble_scan_start, scan_start failed.\n");
          return NRF_BLE_OP_FAILURE;
        }
    }

    return NRF_BLE_OP_SUCCESS;

}

/**@brief Function for initializing the BLE stack.
 *
 * @details Initializes the SoftDevice and the BLE event interrupts.
 */
static int ble_stack_init(void)
{
    ret_code_t err_code;

    err_code = nrf_sdh_enable_request();
    if (err_code != NRF_SUCCESS) {
      printf("in ble_stack_init, nrf_sdh_enable_request failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    // Configure the BLE stack using the default settings.
    // Fetch the start address of the application RAM.
    uint32_t ram_start = 0;
    err_code = nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start);
    if (err_code != NRF_SUCCESS) {
      printf("in ble_stack_init, nf_sdh_ble_default_cfg_set failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    // Overwrite some of the default configurations for the BLE stack.
    ble_cfg_t ble_cfg;

    // Enable BLE stack.
    err_code = nrf_sdh_ble_enable(&ram_start);
    if (err_code != NRF_SUCCESS) {
      printf("in ble_stack_init, nrf_sdh_ble_enable failed.\n");
      return NRF_BLE_OP_FAILURE;
    }

    return NRF_BLE_OP_SUCCESS;
}

/**@brief Function for initializing all things needed for BLE scanning and advertising.
*/
void ble_init() {
    if (ble_stack_init() != NRF_BLE_OP_SUCCESS) {
      printf("in ble_init(), ble_stack_init() failed.\n");
    }
    if (scan_init() != NRF_BLE_OP_SUCCESS) {
      printf("in ble_init(), scan_init() failed.\n");
    }
}