#include <winsock2.h>
#include "hcn_network.h"
#include "ui.h"
#include <stdio.h>
#include <objbase.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

#pragma comment(lib, "ole32.lib")

/* ---- HCN function pointer types ---- */

typedef HRESULT (WINAPI *PFN_HcnCreateNetwork)(
    REFGUID id, PCWSTR settings, void **network, PWSTR *errorRecord);
typedef HRESULT (WINAPI *PFN_HcnCreateEndpoint)(
    void *network, REFGUID id, PCWSTR settings, void **endpoint, PWSTR *errorRecord);
typedef HRESULT (WINAPI *PFN_HcnDeleteNetwork)(
    REFGUID id, PWSTR *errorRecord);
typedef HRESULT (WINAPI *PFN_HcnDeleteEndpoint)(
    REFGUID id, PWSTR *errorRecord);
typedef HRESULT (WINAPI *PFN_HcnCloseNetwork)(void *network);
typedef HRESULT (WINAPI *PFN_HcnCloseEndpoint)(void *endpoint);
typedef HRESULT (WINAPI *PFN_HcnOpenNetwork)(
    REFGUID id, void **network, PWSTR *errorRecord);
typedef HRESULT (WINAPI *PFN_HcnQueryNetworkProperties)(
    void *network, PCWSTR query, PWSTR *properties, PWSTR *errorRecord);

/* ---- Loaded function pointers ---- */

static HMODULE g_hcn_dll = NULL;
static SRWLOCK g_network_lock = SRWLOCK_INIT;

static PFN_HcnCreateNetwork    pfnCreateNet;
static PFN_HcnCreateEndpoint   pfnCreateEp;
static PFN_HcnDeleteNetwork    pfnDeleteNet;
static PFN_HcnDeleteEndpoint   pfnDeleteEp;
static PFN_HcnCloseNetwork     pfnCloseNet;
static PFN_HcnCloseEndpoint    pfnCloseEp;
static PFN_HcnOpenNetwork      pfnOpenNet;
static PFN_HcnQueryNetworkProperties pfnQueryNet;

/* ---- Helpers ---- */

static void guid_to_string(const GUID *g, wchar_t *out, size_t out_len)
{
    swprintf_s(out, out_len,
        L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
        g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

/* ---- Public API ---- */

typedef HRESULT (WINAPI *PFN_HcnEnumerateNetworks)(
    PCWSTR query, PWSTR *networks, PWSTR *errorRecord);

static PFN_HcnEnumerateNetworks pfnEnumNet;

BOOL hcn_init(void)
{
    g_hcn_dll = LoadLibraryW(L"computenetwork.dll");
    if (!g_hcn_dll)
        return FALSE;

    pfnCreateNet  = (PFN_HcnCreateNetwork)GetProcAddress(g_hcn_dll, "HcnCreateNetwork");
    pfnCreateEp   = (PFN_HcnCreateEndpoint)GetProcAddress(g_hcn_dll, "HcnCreateEndpoint");
    pfnDeleteNet  = (PFN_HcnDeleteNetwork)GetProcAddress(g_hcn_dll, "HcnDeleteNetwork");
    pfnDeleteEp   = (PFN_HcnDeleteEndpoint)GetProcAddress(g_hcn_dll, "HcnDeleteEndpoint");
    pfnCloseNet   = (PFN_HcnCloseNetwork)GetProcAddress(g_hcn_dll, "HcnCloseNetwork");
    pfnCloseEp    = (PFN_HcnCloseEndpoint)GetProcAddress(g_hcn_dll, "HcnCloseEndpoint");
    pfnOpenNet    = (PFN_HcnOpenNetwork)GetProcAddress(g_hcn_dll, "HcnOpenNetwork");
    pfnEnumNet    = (PFN_HcnEnumerateNetworks)GetProcAddress(g_hcn_dll, "HcnEnumerateNetworks");
    /* Optional: only needed to list existing Transparent networks for the UI. */
    pfnQueryNet   = (PFN_HcnQueryNetworkProperties)GetProcAddress(g_hcn_dll, "HcnQueryNetworkProperties");

    if (!pfnCreateNet || !pfnCreateEp || !pfnCloseNet || !pfnCloseEp) {
        FreeLibrary(g_hcn_dll);
        g_hcn_dll = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Fixed GUIDs for AppSandbox networks so we can clean up across runs */
static const GUID APPSANDBOX_NAT_GUID = {
    0xA5B01234, 0x5678, 0x9ABC,
    { 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
};

static const GUID APPSANDBOX_INTERNAL_GUID = {
    0xA5B01234, 0x5678, 0x9ABC,
    { 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x77 }
};

static const GUID APPSANDBOX_EXTERNAL_GUID = {
    0xA5B01234, 0x5678, 0x9ABC,
    { 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88 }
};

/* Find the adapter that carries the default route (0.0.0.0/0). */
/* Find a physical adapter that is UP, has a default gateway, and isn't virtual.
   Prefers Ethernet (IF_TYPE_ETHERNET_CSMACD) over Wi-Fi (IF_TYPE_IEEE80211). */
static BOOL get_default_adapter_name(wchar_t *out, size_t out_len)
{
    ULONG buf_len;
    PIP_ADAPTER_ADDRESSES addrs;
    PIP_ADAPTER_ADDRESSES cur;
    PIP_ADAPTER_ADDRESSES best_eth = NULL;
    PIP_ADAPTER_ADDRESSES best_wifi = NULL;
    PIP_ADAPTER_ADDRESSES pick;
    DWORD ret;

    buf_len = 15000;
    addrs = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
    if (!addrs) return FALSE;

    ret = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        NULL, addrs, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
        if (!addrs) return FALSE;
        ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            NULL, addrs, &buf_len);
    }
    if (ret != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, addrs);
        return FALSE;
    }

    for (cur = addrs; cur != NULL; cur = cur->Next) {
        BOOL has_gateway = FALSE;

        /* Must be UP */
        if (cur->OperStatus != IfOperStatusUp)
            continue;

        /* Skip virtual adapters (Hyper-V vSwitch, VPN, loopback) */
        if (wcsstr(cur->FriendlyName, L"vEthernet") != NULL)
            continue;
        if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (cur->IfType == IF_TYPE_TUNNEL)
            continue;

        /* Must have a gateway (i.e. connected to a network with internet) */
        if (cur->FirstGatewayAddress != NULL)
            has_gateway = TRUE;
        if (!has_gateway)
            continue;

        /* Prefer Ethernet over Wi-Fi */
        if (cur->IfType == IF_TYPE_ETHERNET_CSMACD && !best_eth)
            best_eth = cur;
        else if (cur->IfType == IF_TYPE_IEEE80211 && !best_wifi)
            best_wifi = cur;
    }

    pick = best_eth ? best_eth : best_wifi;
    if (pick) {
        wcscpy_s(out, out_len, pick->FriendlyName);
        ui_log(L"Selected adapter: %s (type %lu, index %lu)",
               out, pick->IfType, pick->IfIndex);
        HeapFree(GetProcessHeap(), 0, addrs);
        return TRUE;
    }

    HeapFree(GetProcessHeap(), 0, addrs);
    return FALSE;
}

/* Check if a network already exists by GUID. Returns TRUE if it does. */
static BOOL hcn_network_exists(const GUID *id)
{
    void *network = NULL;
    PWSTR er = NULL;
    HRESULT hr;

    if (!pfnOpenNet) return FALSE;

    hr = pfnOpenNet(id, &network, &er);
    if (er) LocalFree(er);
    if (SUCCEEDED(hr) && network) {
        if (pfnCloseNet) pfnCloseNet(network);
        return TRUE;
    }
    return FALSE;
}

/* Parse a network GUID in either {braced} or bare form. */
static BOOL parse_network_guid(const wchar_t *text, GUID *id)
{
    wchar_t braced[64];
    if (!text || !text[0] || wcslen(text) >= ARRAYSIZE(braced) - 2) return FALSE;
    if (text[0] == L'{') wcscpy_s(braced, ARRAYSIZE(braced), text);
    else swprintf_s(braced, ARRAYSIZE(braced), L"{%s}", text);
    return SUCCEEDED(CLSIDFromString(braced, id));
}

/* Delete all AppSandbox networks by their fixed GUIDs. Fast - no enumeration.
   Call only at startup to clean up stale networks from a previous run; never
   from per-VM create paths, or you'll rip the network out from under any
   already-running VM that's attached to it. */
void hcn_cleanup_stale_networks(void)
{
    PWSTR er = NULL;
    if (!pfnDeleteNet) return;
    pfnDeleteNet(&APPSANDBOX_NAT_GUID, &er);
    if (er) { LocalFree(er); er = NULL; }
    pfnDeleteNet(&APPSANDBOX_INTERNAL_GUID, &er);
    if (er) { LocalFree(er); er = NULL; }
    pfnDeleteNet(&APPSANDBOX_EXTERNAL_GUID, &er);
    if (er) { LocalFree(er); er = NULL; }
}

void hcn_cleanup(void)
{
    if (g_hcn_dll) {
        FreeLibrary(g_hcn_dll);
        g_hcn_dll = NULL;
    }
}

/* -------------------------------------------------------------------------
 *  NAT subnet selection
 *
 *  We use a small fixed list of /24 candidates and pick the first one that
 *  doesn't overlap any IPv4 subnet currently bound to a host adapter.
 *  Default Switch (172.20.48.0/20) is built-in on every Windows 11 host;
 *  192.168.42.0/24 sidesteps it. The fallback 192.168.142.0/24 covers the
 *  unlikely case where the user's home network or VPN claims .42.
 *
 *  Decided once on first call, stable for process lifetime. No saved-state
 *  coordination, no per-VM adoption -- the same probe runs every start.
 *  HCN's startup network-delete (hcn_cleanup_stale_networks) wipes the
 *  previous run's network so the freshly-picked subnet is always honored.
 * ------------------------------------------------------------------------- */

static char g_nat_base[16];   /* "192.168.42" or "192.168.142", no trailing dot */

typedef struct { DWORD network; int prefix_len; } SubnetInfo;

static BOOL ranges_overlap(DWORD a_net, int a_prefix, DWORD b_net, int b_prefix)
{
    DWORD a_mask = (a_prefix == 0) ? 0 : (~0u << (32 - a_prefix));
    DWORD b_mask = (b_prefix == 0) ? 0 : (~0u << (32 - b_prefix));
    DWORD a_start = a_net & a_mask;
    DWORD a_end   = a_start | ~a_mask;
    DWORD b_start = b_net & b_mask;
    DWORD b_end   = b_start | ~b_mask;
    return (a_start <= b_end) && (b_start <= a_end);
}

static int collect_inuse_subnets(SubnetInfo *out, int cap)
{
    ULONG size = 0;
    int n = 0;
    PIP_ADAPTER_ADDRESSES buf = NULL;
    PIP_ADAPTER_ADDRESSES a;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                          NULL, NULL, &size);
    if (size == 0) return 0;
    buf = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (!buf) return 0;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                              NULL, buf, &size) != NO_ERROR) {
        free(buf); return 0;
    }
    for (a = buf; a && n < cap; a = a->Next) {
        PIP_ADAPTER_UNICAST_ADDRESS u;
        for (u = a->FirstUnicastAddress; u && n < cap; u = u->Next) {
            SOCKADDR_IN *sin;
            if (!u->Address.lpSockaddr) continue;
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            if (u->OnLinkPrefixLength > 32) continue;
            sin = (SOCKADDR_IN *)u->Address.lpSockaddr;
            out[n].network    = ntohl(sin->sin_addr.s_addr);
            out[n].prefix_len = u->OnLinkPrefixLength;
            n++;
        }
    }
    free(buf);
    return n;
}

static void pick_nat_base_once(void)
{
    static const char *CANDIDATES[] = { "192.168.42", "192.168.142", NULL };
    SubnetInfo used[64];
    int n_used, i, j;

    if (g_nat_base[0]) return;

    n_used = collect_inuse_subnets(used, 64);
    for (i = 0; CANDIDATES[i]; i++) {
        int a, b, c;
        DWORD candidate;
        BOOL conflict = FALSE;
        if (sscanf_s(CANDIDATES[i], "%d.%d.%d", &a, &b, &c) != 3) continue;
        candidate = ((DWORD)a << 24) | ((DWORD)b << 16) | ((DWORD)c << 8);
        for (j = 0; j < n_used; j++) {
            if (ranges_overlap(candidate, 24, used[j].network, used[j].prefix_len)) {
                conflict = TRUE; break;
            }
        }
        if (!conflict) {
            strcpy_s(g_nat_base, sizeof(g_nat_base), CANDIDATES[i]);
            ui_log(L"NAT subnet: %S.0/24 (gateway %S.1)", g_nat_base, g_nat_base);
            return;
        }
    }
    strcpy_s(g_nat_base, sizeof(g_nat_base), CANDIDATES[0]);
    ui_log(L"WARNING: every candidate NAT subnet (192.168.42.0/24, 192.168.142.0/24) overlaps a host adapter. "
           L"Using %S.0/24 anyway; HCN create may fail. Edit hcn_network.c CANDIDATES to add another.",
           g_nat_base);
}

const char *hcn_nat_subnet_base(void)
{
    AcquireSRWLockExclusive(&g_network_lock);
    pick_nat_base_once();
    ReleaseSRWLockExclusive(&g_network_lock);
    return g_nat_base;
}

HRESULT hcn_create_nat_network(GUID *network_id)
{
    wchar_t settings[1024];
    void *network = NULL;
    PWSTR error_record = NULL;
    HRESULT hr;

    if (!g_hcn_dll || !pfnCreateNet)
        return E_NOT_VALID_STATE;

    *network_id = APPSANDBOX_NAT_GUID;

    AcquireSRWLockExclusive(&g_network_lock);
    /* Reuse the existing AppSandbox NAT network if it's already up -
       multiple VMs share one network, each with its own endpoint. */
    if (hcn_network_exists(&APPSANDBOX_NAT_GUID)) {
        ReleaseSRWLockExclusive(&g_network_lock);
        return S_OK;
    }

    pick_nat_base_once();

    swprintf_s(settings, 1024,
        L"{"
        L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
        L"\"Name\":\"AppSandboxNAT\","
        L"\"Type\":\"NAT\","
        L"\"Ipams\":[{"
            L"\"Type\":\"Static\","
            L"\"Subnets\":[{"
                L"\"IpAddressPrefix\":\"%S.0/24\","
                L"\"Routes\":[{\"NextHop\":\"%S.1\",\"DestinationPrefix\":\"0.0.0.0/0\"}]"
            L"}]"
        L"}]"
        L"}",
        g_nat_base, g_nat_base);

    hr = pfnCreateNet(network_id, settings, &network, &error_record);

    if (error_record) {
        if (FAILED(hr)) ui_log(L"HCN NAT error: %s", error_record);
        LocalFree(error_record);
    }
    if (network && pfnCloseNet)
        pfnCloseNet(network);

    ReleaseSRWLockExclusive(&g_network_lock);
    return hr;
}

HRESULT hcn_create_internal_network(GUID *network_id)
{
    wchar_t settings[1024];
    void *network = NULL;
    PWSTR error_record = NULL;
    HRESULT hr;

    if (!g_hcn_dll || !pfnCreateNet)
        return E_NOT_VALID_STATE;

    *network_id = APPSANDBOX_INTERNAL_GUID;

    AcquireSRWLockExclusive(&g_network_lock);
    if (hcn_network_exists(&APPSANDBOX_INTERNAL_GUID)) {
        ReleaseSRWLockExclusive(&g_network_lock);
        return S_OK;
    }

    swprintf_s(settings, 1024,
        L"{"
        L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
        L"\"Name\":\"AppSandboxInternal\","
        L"\"Type\":\"ICS\""
        L"}");

    hr = pfnCreateNet(network_id, settings, &network, &error_record);

    if (error_record) {
        if (FAILED(hr)) ui_log(L"HCN Internal error: %s", error_record);
        LocalFree(error_record);
    }
    if (network && pfnCloseNet) pfnCloseNet(network);

    ReleaseSRWLockExclusive(&g_network_lock);
    return hr;
}

HRESULT hcn_create_external_network(GUID *network_id, const wchar_t *adapter_name)
{
    wchar_t settings[2048];
    wchar_t adapter[256];
    void *network = NULL;
    PWSTR error_record = NULL;
    HRESULT hr;

    if (!g_hcn_dll || !pfnCreateNet)
        return E_NOT_VALID_STATE;

    /* A GUID selects an existing HNS network (for example a Hyper-V vSwitch's
       Transparent network). Borrowed networks are never deleted; see
       hcn_delete_network. */
    if (adapter_name && adapter_name[0]) {
        GUID existing;
        if (parse_network_guid(adapter_name, &existing)) {
            if (!hcn_network_exists(&existing)) {
                ui_log(L"External network %s does not exist.", adapter_name);
                return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            }
            *network_id = existing;
            ui_log(L"Using existing HNS network %s", adapter_name);
            return S_OK;
        }
    }

    *network_id = APPSANDBOX_EXTERNAL_GUID;

    AcquireSRWLockExclusive(&g_network_lock);
    if (hcn_network_exists(&APPSANDBOX_EXTERNAL_GUID)) {
        ReleaseSRWLockExclusive(&g_network_lock);
        return S_OK;
    }

    /* Use specified adapter, or auto-detect */
    if (adapter_name && adapter_name[0] != L'\0') {
        wcscpy_s(adapter, 256, adapter_name);
        ui_log(L"Using adapter: %s", adapter);
    } else {
        if (!get_default_adapter_name(adapter, 256)) {
            ui_log(L"Error: No connected network adapter found for External network.");
            ReleaseSRWLockExclusive(&g_network_lock);
            return E_FAIL;
        }
    }

    swprintf_s(settings, 2048,
        L"{"
        L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
        L"\"Name\":\"AppSandboxExternal\","
        L"\"Type\":\"Transparent\","
        L"\"Policies\":[{\"Type\":\"NetAdapterName\",\"Settings\":{\"NetworkAdapterName\":\"%s\"}}]"
        L"}", adapter);

    hr = pfnCreateNet(network_id, settings, &network, &error_record);

    if (error_record) {
        if (FAILED(hr)) ui_log(L"HCN External error: %s", error_record);
        LocalFree(error_record);
    }
    if (network && pfnCloseNet) pfnCloseNet(network);

    ReleaseSRWLockExclusive(&g_network_lock);
    return hr;
}

static BOOL valid_mac_address(const wchar_t *address)
{
    size_t i;
    if (wcslen(address) != 17) return FALSE;
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (address[i] != L'-' && address[i] != L':') return FALSE;
        } else if (!wcschr(L"0123456789abcdefABCDEF", address[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

HRESULT hcn_create_endpoint(const GUID *network_id, GUID *endpoint_id,
                            wchar_t *endpoint_guid_str, size_t str_len,
                            const char *nat_ip, const wchar_t *mac_address)
{
    wchar_t net_guid_str[64];
    wchar_t ep_guid_str[64];
    wchar_t settings[1024];
    wchar_t mac_settings[64] = L"";
    void *network = NULL;
    void *endpoint = NULL;
    PWSTR error_record = NULL;
    HRESULT hr;

    if (!g_hcn_dll || !pfnCreateEp || !pfnOpenNet)
        return E_NOT_VALID_STATE;
    if (!mac_address || !valid_mac_address(mac_address))
        return E_INVALIDARG;
    swprintf_s(mac_settings, ARRAYSIZE(mac_settings), L",\"MacAddress\":\"%s\"", mac_address);

    /* Open the network */
    hr = pfnOpenNet(network_id, &network, &error_record);
    if (error_record) { LocalFree(error_record); error_record = NULL; }
    if (FAILED(hr)) return hr;

    CoCreateGuid(endpoint_id);
    guid_to_string(network_id, net_guid_str, 64);
    guid_to_string(endpoint_id, ep_guid_str, 64);

    /* Static IP for NAT; DHCP for Internal (ICS) and External (Transparent) */
    if (IsEqualGUID(network_id, &APPSANDBOX_NAT_GUID) && nat_ip && nat_ip[0]) {
        swprintf_s(settings, 1024,
            L"{"
            L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
            L"\"HostComputeNetwork\":\"%s\","
            L"\"IpConfigurations\":[{\"IpAddress\":\"%S\",\"PrefixLength\":24}]"
            L"%s}", net_guid_str, nat_ip, mac_settings);
    } else if (IsEqualGUID(network_id, &APPSANDBOX_NAT_GUID)) {
        hcn_nat_subnet_base();
        swprintf_s(settings, 1024,
            L"{"
            L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
            L"\"HostComputeNetwork\":\"%s\","
            L"\"IpConfigurations\":[{\"IpAddress\":\"%S.2\",\"PrefixLength\":24}]"
            L"%s}", net_guid_str, g_nat_base, mac_settings);
    } else {
        /* Internal (ICS DHCP) or External (LAN DHCP) - no static IP */
        swprintf_s(settings, 1024,
            L"{"
            L"\"SchemaVersion\":{\"Major\":2,\"Minor\":0},"
            L"\"HostComputeNetwork\":\"%s\""
            L"%s}", net_guid_str, mac_settings);
    }

    hr = pfnCreateEp(network, endpoint_id, settings, &endpoint, &error_record);

    if (SUCCEEDED(hr) && endpoint_guid_str) {
        wcscpy_s(endpoint_guid_str, str_len, ep_guid_str);
    }

    if (error_record) {
        if (FAILED(hr)) ui_log(L"HCN Endpoint error: %s", error_record);
        LocalFree(error_record);
    }
    if (endpoint && pfnCloseEp) pfnCloseEp(endpoint);
    if (network && pfnCloseNet) pfnCloseNet(network);

    return hr;
}

HRESULT hcn_delete_network(const GUID *network_id)
{
    PWSTR error_record = NULL;
    HRESULT hr;
    wchar_t guid_str[64];

    if (!g_hcn_dll || !pfnDeleteNet)
        return E_NOT_VALID_STATE;

    StringFromGUID2(network_id, guid_str, 64);

    /* Only fixed AppSandbox GUIDs are ours. A borrowed network (for example
       a Hyper-V vSwitch) must survive VM stop/delete/startup cleanup. */
    if (!IsEqualGUID(network_id, &APPSANDBOX_NAT_GUID) &&
        !IsEqualGUID(network_id, &APPSANDBOX_INTERNAL_GUID) &&
        !IsEqualGUID(network_id, &APPSANDBOX_EXTERNAL_GUID)) {
        ui_log(L"HCN: leaving borrowed network %s intact.", guid_str);
        return S_OK;
    }

    ui_log(L"HCN: Deleting network %s...", guid_str);

    hr = pfnDeleteNet(network_id, &error_record);
    if (SUCCEEDED(hr)) {
        ui_log(L"HCN: Network deleted.");
    } else {
        ui_log(L"HCN: Delete network failed (0x%08X).", hr);
        if (error_record) {
            ui_log(L"HCN error: %s", error_record);
        }
    }
    if (error_record) LocalFree(error_record);
    return hr;
}

HRESULT hcn_delete_endpoint(const GUID *endpoint_id)
{
    PWSTR error_record = NULL;
    HRESULT hr;
    wchar_t guid_str[64];

    if (!g_hcn_dll || !pfnDeleteEp)
        return E_NOT_VALID_STATE;

    StringFromGUID2(endpoint_id, guid_str, 64);
    ui_log(L"HCN: Deleting endpoint %s...", guid_str);

    hr = pfnDeleteEp(endpoint_id, &error_record);
    if (SUCCEEDED(hr)) {
        ui_log(L"HCN: Endpoint deleted.");
    } else {
        ui_log(L"HCN: Delete endpoint failed (0x%08X).", hr);
        if (error_record) {
            ui_log(L"HCN error: %s", error_record);
        }
    }
    if (error_record) LocalFree(error_record);
    return hr;
}

int hcn_enum_adapters(HcnAdapterCallback cb, void *ctx)
{
    ULONG buf_len = 15000;
    PIP_ADAPTER_ADDRESSES addrs, cur;
    DWORD ret;
    int count = 0;

    addrs = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
    if (!addrs) return 0;

    ret = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        NULL, addrs, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
        if (!addrs) return 0;
        ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            NULL, addrs, &buf_len);
    }

    if (ret == ERROR_SUCCESS) {
        for (cur = addrs; cur != NULL; cur = cur->Next) {
            if (cur->OperStatus != IfOperStatusUp) continue;
            if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (cur->IfType == IF_TYPE_TUNNEL) continue;
            if (wcsstr(cur->FriendlyName, L"vEthernet") != NULL) continue;

            cb(cur->FriendlyName, (int)cur->IfType, ctx);
            count++;
        }
    }

    HeapFree(GetProcessHeap(), 0, addrs);
    return count;
}

/* Read the next quoted string from a JSON string array. Advances *cursor. */
static BOOL next_json_string(const wchar_t **cursor, wchar_t *out, size_t out_len)
{
    const wchar_t *p;
    size_t n = 0;

    if (!cursor || !*cursor || !out || out_len == 0) return FALSE;
    p = *cursor;
    while (*p && *p != L'"') p++;          /* skip separators and whitespace */
    if (!*p) return FALSE;
    p++;
    while (*p && *p != L'"' && n + 1 < out_len) {
        if (*p == L'\\' && p[1]) p++;      /* \" \\ \/ are literal next char */
        out[n++] = *p++;
    }
    while (*p && *p != L'"') p++;          /* overlong value: skip what we cut */
    if (*p == L'"') p++;
    out[n] = L'\0';
    *cursor = p;
    return TRUE;
}

/* Copy the string value of a JSON key out of a flat properties object. */
static BOOL json_string_value(const wchar_t *json, const wchar_t *key,
                              wchar_t *out, size_t out_len)
{
    const wchar_t *p;
    int depth = 0;
    size_t n = 0;

    if (!json || !key || !out || out_len == 0 || json[0] != L'{') return FALSE;
    p = json;
    while (*p) {
        if (*p == L'"') {
            wchar_t found[64];
            size_t fn = 0;
            p++;
            while (*p && *p != L'"' && fn + 1 < ARRAYSIZE(found)) {
                if (*p == L'\\' && p[1]) p++;
                found[fn++] = *p++;
            }
            found[fn] = L'\0';
            while (*p && *p != L'"') p++;
            if (*p == L'"') p++;
            if (depth != 1 || wcscmp(found, key) != 0) continue;
            while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n') p++;
            if (*p != L':') return FALSE;
            p++;
            while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n') p++;
            if (*p != L'"') return FALSE;
            p++;
            while (*p && *p != L'"' && n + 1 < out_len) {
                if (*p == L'\\' && p[1]) {
                    p++;
                    switch (*p) {
                    case L'n': out[n++] = L'\n'; break;
                    case L'r': out[n++] = L'\r'; break;
                    case L't': out[n++] = L'\t'; break;
                    case L'u':
                        /* \uXXXX; switch names are plain ASCII in practice. */
                        p += (wcslen(p) >= 5) ? 5 : wcslen(p);
                        continue;
                    default: out[n++] = *p; break;  /* \" \\ \/ */
                    }
                    p++;
                } else {
                    out[n++] = *p++;
                }
            }
            out[n] = L'\0';
            return TRUE;
        }
        if (*p == L'{' || *p == L'[') depth++;
        else if (*p == L'}' || *p == L']') depth--;
        p++;
    }
    return FALSE;
}

int hcn_enum_switches(HcnSwitchCallback cb, void *ctx)
{
    PWSTR networks = NULL, error = NULL;
    const wchar_t *cursor;
    HRESULT hr;
    int count = 0;

    if (!g_hcn_dll || !pfnEnumNet || !pfnOpenNet || !pfnQueryNet || !cb)
        return 0;

    hr = pfnEnumNet(L"{}", &networks, &error);
    if (error) LocalFree(error);
    if (FAILED(hr) || !networks) {
        if (networks) LocalFree(networks);
        return 0;
    }

    cursor = networks;
    while (count < 32) {
        wchar_t text[64];
        wchar_t name[256];
        GUID id;
        void *network = NULL;
        PWSTR props = NULL, query_error = NULL;

        if (!next_json_string(&cursor, text, ARRAYSIZE(text))) break;
        if (!parse_network_guid(text, &id)) continue;
        if (IsEqualGUID(&id, &APPSANDBOX_NAT_GUID) ||
            IsEqualGUID(&id, &APPSANDBOX_INTERNAL_GUID) ||
            IsEqualGUID(&id, &APPSANDBOX_EXTERNAL_GUID))
            continue;

        hr = pfnOpenNet(&id, &network, &query_error);
        if (query_error) { LocalFree(query_error); query_error = NULL; }
        if (FAILED(hr) || !network) {
            if (network && pfnCloseNet) pfnCloseNet(network);
            continue;
        }

        hr = pfnQueryNet(network, L"{}", &props, &query_error);
        if (query_error) { LocalFree(query_error); query_error = NULL; }
        if (SUCCEEDED(hr) && props && wcsstr(props, L"\"Type\":\"Transparent\"")) {
            if (!json_string_value(props, L"Name", name, ARRAYSIZE(name)) || !name[0])
                wcscpy_s(name, ARRAYSIZE(name), text);
            cb(name, &id, ctx);
            count++;
        }
        if (props) LocalFree(props);
        if (pfnCloseNet) pfnCloseNet(network);
    }

    LocalFree(networks);
    return count;
}
