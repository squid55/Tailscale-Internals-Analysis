# Tailscale Internals Analysis

Tailscale의 내부 구현, WireGuard 프로토콜, Linux 커널 통합에 대한 심층 기술 분석 문서.

## Contents

- [전체 분석 문서 (한국어)](./Tailscale-내부구현-분석.md)

## Topics Covered

### 1. WireGuard Protocol
- Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s 핸드셰이크
- Curve25519 DH 연산 순서 (ee, se, ss)
- ChaCha20-Poly1305 AEAD 전송 암호화
- HKDF-BLAKE2s 키 유도 체인
- 핸드셰이크 메시지 구조 (148B Initiation, 92B Response)

### 2. Linux Kernel Integration
- TUN device (`/dev/net/tun`, `ioctl TUNSETIFF`)
- Userspace WireGuard (wireguard-go) vs kernel module 선택 이유
- Netfilter/iptables/nftables 규칙 생성 및 관리
- Policy-based routing (`ip rule`, `ip route`, netlink)

### 3. NAT Traversal
- STUN을 통한 공개 엔드포인트 발견
- DERP (Designated Encrypted Relay for Packets) 릴레이
- Disco 프로토콜 (Ping/Pong/CallMeMaybe)
- Birthday Paradox 기법 (Hard NAT 관통)
- UPnP/NAT-PMP/PCP 포트 매핑

### 4. Control Plane
- Coordination server 아키텍처
- 4종 키 관리 (Machine/Node/Disco/WireGuard Key)
- NetworkMap 배포 및 ACL 적용
- 컨트롤/데이터 플레인 분리

### 5. tailscaled Architecture
- LocalBackend 오케스트레이터
- magicsock.Conn 적응형 전송
- MagicDNS 3계층 (Manager/Resolver/Forwarder)
- 서브넷 라우팅 / 출구 노드 구현

## References

- [Tailscale: How it works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
- [WireGuard Protocol & Cryptography](https://www.wireguard.com/protocol/)
- [Tailscale Key Management](https://tailscale.com/blog/tailscale-key-management)
- [Linux TUN/TAP Documentation](https://www.kernel.org/doc/html/latest/networking/tuntap.html)

## License

This analysis is for educational purposes. All referenced technologies belong to their respective owners.
