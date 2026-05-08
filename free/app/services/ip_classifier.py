"""
ip_classifier.py — User CIDR 기반 IP 분류
User 대역 포함 = User, 그 외 = Server, 대역 미설정 = Unknown
"""
import ipaddress


def classify_ip(addr_list, user_ranges: list) -> str:
    if not user_ranges:
        return "Unknown"
    items = addr_list if isinstance(addr_list, list) else [addr_list]
    for addr in items:
        try:
            ip = ipaddress.ip_network(str(addr).strip(), strict=False)
            for entry in user_ranges:
                net = ipaddress.ip_network(entry["cidr"], strict=False)
                if ip.overlaps(net):
                    return "User"
        except Exception:
            continue
    return "Server"


def classify_traffic_type(src_list, dst_list, user_ranges: list) -> str:
    """반환: "Server-Server", "Server-User", "Unknown" """
    if not user_ranges:
        return "Unknown"
    src_t = classify_ip(src_list, user_ranges)
    dst_t = classify_ip(dst_list, user_ranges)
    if "Unknown" in (src_t, dst_t):
        return "Unknown"
    if src_t == "Server" and dst_t == "Server":
        return "Server-Server"
    return "Server-User"
