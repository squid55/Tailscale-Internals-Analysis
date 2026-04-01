# Tailscale 내부 구현 심층 분석

## 연관 프로젝트
- [[멀티보드-카메라-스트리밍-시스템]] — Tailscale VPN 인프라 (구축 완료)
- [[멀티보드-분산협업-시스템]] — 외부 접속 경로
- [[Jetson-Zybo-AI카메라-통합프로젝트]] — 네트워크 백본

---

## 0. 아키텍처 개요: 왜 Tailscale인가

### 0.1 네트워크 토폴로지 비교

Tailscale은 하이브리드 중앙-분산 모델이다. **컨트롤 플레인**(hub-and-spoke)과 **데이터 플레인**(mesh)이 분리되어 있다.

**Hub-and-Spoke (전통 VPN):**
```
                 ┌──────────────┐
    ┌───────────>│  VPN 집중기   │<───────────┐
    │            │ (정적 IP, 오픈 포트) │       │
    │            └──────────────┘            │
    │                    ↑                   │
 뉴욕 사용자       샌프란시스코 본사       뉴욕 서버
```
- 모든 트래픽이 중앙 집중기를 경유
- 뉴욕 사용자 → 뉴욕 서버 연결에도 샌프란시스코를 왕복 (이중 레이턴시)
- 집중기가 병목 + 단일 장애점

**Multi-Hub:**
- 여러 데이터센터에 허브 분산 배치
- 각 데이터센터에 정적 IP + 오픈 포트 + WireGuard 키 등록 필요
- 여전히 허브를 경유하는 중앙 라우팅

**Mesh (Tailscale 방식):**
```
  노드A ◄════════► 노드B
    ↑  ╲              ↑
    │    ╲             │
    │     ╲            │
    ↓      ╲           ↓
  노드C ◄════╲═══► 노드D
               ╲       ↑
                ╲      │
                 ↓     │
                노드E ─┘
```
- 모든 노드가 직접 연결 → 최소 레이턴시
- 문제: 10노드 → 90개 엔드포인트 구성 필요, 동적 IP, 방화벽 관통
- **Tailscale이 이 복잡성을 자동 해결**: 코디네이션 서버 + NAT traversal + 동적 피어 관리

### 0.2 전통 VPN과의 근본적 차이

> *"VPNs really fit in the category of 'connectivity' software: they increase the number of devices that can get into your private network. They don't decrease it, like security software would."*
> — Tailscale 공식 블로그

| 측면 | 전통 VPN | Tailscale |
|------|----------|-----------|
| 본질 | **연결성** 소프트웨어 (접근 가능 기기를 늘림) | **연결성 + 보안** (메시 + ACL + E2E 암호화) |
| 데이터 경로 | 중앙 집중기 경유 | 직접 피어 투 피어 |
| 확장성 | 노드 증가 → 집중기 부하 증가 | 노드 증가 → 처리 능력도 분산 증가 |
| 암호화 | 집중기에서 복호화 후 재암호화 | **종단간 암호화 (중간자가 복호화 불가)** |
| 인증 | VPN과 별도의 인증 시스템 | 기존 IdP (Google/MS/Okta) 통합 |
| 배포 | 하드웨어/서버 설치 필요 | 소프트웨어만, 2분 셋업 |

### 0.3 점진적 배포 모델

Tailscale은 전부-아니면-전무 마이그레이션이 아닌 **점진적 도입**을 지원한다:

1. **시작**: 두 기기에 설치 → 동일 계정 로그인 → 즉시 메시 형성
2. **확장**: 서브넷 라우트로 기존 사무실/데이터센터 연결 (기존 인프라 유지)
3. **심화**: 서버/컨테이너에 개별 설치 → 포인트 투 포인트 암호화
4. **완성**: 전체 제로 트러스트 네트워킹 (비암호화 LAN 트래픽 없음)

### 0.4 오픈소스 구성요소

- **tailscale 노드 소프트웨어**: 오픈소스 (클라이언트)
- **DERP 릴레이 서버 코드**: 오픈소스 → 자체 호스팅 가능
- **wireguard-go**: Tailscale이 패치 기여, upstream과 협력 개발

---

## 1. WireGuard 프로토콜 내부 구조

### 1.1 Noise 프로토콜 프레임워크

Tailscale의 암호화 기반은 WireGuard이며, WireGuard는 **`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`** 구성을 사용한다:

| 구성 요소 | 의미 |
|-----------|------|
| **IK** | Initiator가 정적 공개키를 즉시 전송, Responder 키는 사전에 알려짐 |
| **psk2** | 두 번째 핸드셰이크 메시지에서 Pre-Shared Key 혼합 |
| **25519** | Curve25519 타원곡선 DH |
| **ChaChaPoly** | ChaCha20-Poly1305 AEAD 대칭 암호화 |
| **BLAKE2s** | 해시 함수 (32바이트 출력) |

### 1.2 핸드셰이크 메시지 형식

WireGuard는 4가지 메시지 타입을 정의한다:

| 타입 | 값 | 크기 | 용도 |
|------|-----|------|------|
| MessageInitiation | 1 | 148 바이트 | 핸드셰이크 개시 |
| MessageResponse | 2 | 92 바이트 | 핸드셰이크 응답 |
| MessageCookieReply | 3 | 64 바이트 | DoS 방어용 쿠키 |
| MessageTransport | 4 | 가변 | 데이터 전송 |

**핸드셰이크 개시 메시지 구조 (148 바이트):**

```c
struct MessageInitiation {
    u8  message_type;              // 1
    u8  reserved_zero[3];          // 0x000000
    u32 sender_index;              // 세션 식별자 (리틀엔디안)
    u8  unencrypted_ephemeral[32]; // 임시 공개키 (평문)
    u8  encrypted_static[48];      // AEAD(정적 공개키 32B + 태그 16B)
    u8  encrypted_timestamp[28];   // AEAD(타임스탬프 12B + 태그 16B)
    u8  mac1[16];                  // BLAKE2s MAC
    u8  mac2[16];                  // 쿠키 MAC (DoS 보호)
};
```

### 1.3 Diffie-Hellman 연산 순서

핸드셰이크는 3번의 DH 연산을 수행하여 **순방향 비밀성(Forward Secrecy)**을 보장한다:

1. **ee** (ephemeral-ephemeral): 양측 임시키 간 DH
2. **se** (static-ephemeral): 개시자 정적키 + 응답자 임시키
3. **ss** (static-static): 양측 정적키 (사전 계산 가능)

각 DH 결과는 chain key에 혼합되며, KDF는 **HKDF-BLAKE2s**를 사용한다:

- **KDF1**: 단일 출력 도출 — `HMAC-BLAKE2s(key, input, 32)`
- **KDF2**: 이중 출력 — 대칭키 생성용
- **KDF3**: 삼중 출력 — PSK 혼합 시 사용

### 1.4 전송 데이터 형식

```
[메시지 타입: 4B] [수신자 인덱스: 4B] [카운터: 8B] [암호문]
```

- 카운터는 패킷마다 증가, 슬라이딩 윈도우 기반 리플레이 보호
- `mac1`: rate limiting 용 (전체 핸드셰이크 없이 검증 가능)
- `mac2`: 서버 부하 시에만 쿠키 기반 인증

---

## 2. Linux 커널 통합

### 2.1 TUN 디바이스 (`/dev/net/tun`)

Tailscale은 `tailscale0`이라는 **TUN 인터페이스**를 생성한다:

```c
// 1. 캐릭터 디바이스 열기
int fd = open("/dev/net/tun", O_RDWR);

// 2. ifreq 구조체 설정
struct ifreq ifr;
ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // L3 TUN 모드, 패킷 헤더 없음
strncpy(ifr.ifr_name, "tailscale0", IFNAMSIZ);

// 3. ioctl로 커널에 인터페이스 등록
ioctl(fd, TUNSETIFF, &ifr);
```

- `IFF_TUN`: L3(IP) 레벨 터널 (L2인 TAP이 아님)
- `IFF_NO_PI`: 패킷 정보 헤더 생략 — 순수 IP 패킷만 전달
- **fd가 닫히면 인터페이스와 관련 라우트가 자동 삭제** — tailscaled 종료 시 자동 정리

Tailscale 소스에서는 `tstun.New()` -> `tstun.Wrapper`로 래핑하여 패킷 필터링, ACL 적용, 라우트 통합을 처리한다.

### 2.2 Userspace vs Kernel-space WireGuard

**Tailscale의 선택: 유저스페이스 (`wireguard-go` 포크)**

Linux 5.6+에 커널 WireGuard 모듈이 내장되어 있지만, Tailscale은 **의도적으로 사용하지 않는다**:

| 이유 | 설명 |
|------|------|
| **MagicSock 통합** | `magicsock.Conn`이 WireGuard의 `conn.Bind` 인터페이스를 대체. NAT traversal, DERP 릴레이, 경로 전환이 이 레이어에서 투명 처리 |
| **동적 피어 관리** | 바닐라 WireGuard는 정적 피어. Tailscale은 피어를 동적 추가/제거 |
| **Disco 프로토콜** | WireGuard 터널 외부에서 자체 디스커버리 프로토콜 실행 필요 |
| **크로스플랫폼** | 모든 OS에서 동일 코드 경로 |

```
wireguard-go (포크)
  └── conn.Bind 인터페이스
        └── magicsock.Conn
              ├── NAT traversal (STUN + Disco)
              ├── DERP 릴레이 폴백
              └── 직접 UDP 연결
                    ↕
            TUN 디바이스 (tailscale0)
```

### 2.3 Netfilter/iptables/nftables 상호작용

Tailscale은 3가지 netfilter 모드를 지원한다:

| 모드 | 설명 |
|------|------|
| `NetfilterOn` (기본) | 전체 규칙셋. 서브넷 라우팅, 출구 노드 지원 |
| `NetfilterNoDivert` | ACCEPT 규칙만. 포워딩 없음 |
| `NetfilterOff` | netfilter 미수정. 수동 관리 |

**`NetfilterOn`에서 생성되는 규칙:**

```bash
# filter 테이블
-A ts-input -i tailscale0 -j ACCEPT               # tailscale0 인바운드 허용
-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP  # CGNAT 스푸핑 차단
-A ts-input -p udp --dport <tailscale-port> -j ACCEPT  # WireGuard UDP 허용
-A ts-forward -i tailscale0 -j MARK --set-mark 0x40000
-A ts-forward -m mark --mark 0x40000 -j ACCEPT    # 서브넷 라우팅 포워딩

# nat 테이블
-A ts-postrouting -m mark --mark 0x40000 -j MASQUERADE  # SNAT
```

**nftables 모드**: 자체 테이블 생성, **nftables Netlink API를 직접 사용** (`nft` 바이너리 불필요). iptables보다 우선 감지.

### 2.4 라우팅 테이블 조작

```go
type Config struct {
    LocalAddrs    []netip.Prefix  // 노드의 Tailscale IP
    Routes        []netip.Prefix  // Tailscale을 통해 라우팅할 프리픽스
    LocalRoutes   []netip.Prefix  // Tailscale 우회 로컬 네트워크
    SubnetRoutes  []netip.Prefix  // 광고할 서브넷
}
```

- **정책 기반 라우팅** (`ip rule` + `ip route`): Tailscale 트래픽을 별도 라우팅 테이블로 분리
- **Netlink 소켓**: 라우트 설치는 netlink 연산으로 수행
- **`LocalRoutes`**: 출구 노드 사용 시 로컬 트래픽이 Tailscale을 우회하도록 보장 — 라우팅 루프 방지

---

## 3. NAT Traversal

### 3.1 연결 수립 흐름

```
노드 A                    DERP 릴레이                   노드 B
  |                          |                           |
  |---- WG 패킷 (DERP) ---->|------ WG 패킷 전달 ------>|
  |                          |                           |
  |<-- STUN: 공개 IP:포트 --|                           |
  |                          |           STUN: 공개 IP:포트 -->|
  |                          |                           |
  |<====== Disco Ping/Pong (직접 UDP) =================>|
  |                          |                           |
  |<======== WireGuard 직접 터널 (UDP) ================>|
  |         (DERP 자동 해제)                             |
```

1. **DERP 경유로 초기 연결** (항상 성공 보장)
2. **STUN으로 공개 IP:포트 발견**
3. **Disco 프로토콜로 직접 UDP 시도**
4. **성공 시 투명하게 직접 연결로 전환**

### 3.2 NAT 분류

- **Easy NAT (~94%)** — Endpoint-Independent Mapping. 목적지와 무관하게 일관된 외부 포트. STUN 결과 그대로 사용 가능
- **Hard NAT (~6%)** — Endpoint-Dependent Mapping (Symmetric NAT). 각 목적지마다 다른 외부 포트 할당

### 3.3 Hard NAT: Birthday Paradox 기법

Hard NAT 환경에서의 해결:
- 송신 측이 **256개 포트**를 열고
- 수신 측이 무작위 목적지 포트를 탐색
- 초당 100패킷 기준 **~2초 내 50% 성공률**

### 3.4 포트 매핑 프로토콜

| 프로토콜 | 특성 |
|----------|------|
| **UPnP IGD** | XML 기반, 널리 구현, 보안 우려 |
| **NAT-PMP** | Apple 제안, 단순화 |
| **PCP** (RFC 6887) | NAT-PMP 후속, 공개 포트포워딩 |

### 3.5 Disco (Discovery) 프로토콜

Tailscale 자체 NAT traversal 프로토콜:

| 메시지 타입 | 용도 |
|-------------|------|
| `TypePing` | 경로 프로빙 |
| `TypePong` | Ping 응답 (12바이트 TxID 매칭) |
| `TypeCallMeMaybe` | 직접 연결 희망 + 후보 엔드포인트 공유 |
| `TypeBindUDPRelayEndpoint` | UDP 릴레이 엔드포인트 바인딩 |

**엔드포인트 레이싱**: 모든 후보에 동시 ping -> 첫 pong 성공이 `bestAddr` -> trust period(5초)로 플래핑 방지

**경로 품질 우선순위**: 직접 UDP > 피어 릴레이 > DERP 폴백 -> 동일 타입이면 레이턴시 비교 -> 동일하면 Wire MTU로 타이브레이크

### 3.6 DERP (Designated Encrypted Relay for Packets)

TURN 대신 Tailscale 자체 개발한 릴레이:

- **TCP 기반** (TLS, 포트 443) — 엄격한 방화벽도 통과
- 목적지 공개키 기반으로 암호화된 패킷을 **맹목적으로 전달**
- **DERP 서버는 절대 트래픽을 복호화할 수 없다** — WireGuard 암호화가 이미 적용된 상태
- 이중 역할: 폴백 연결성 + NAT traversal 사이드 채널

### 3.7 NAT 수명 프로빙

3단계 cliff 프로빙으로 NAT 타임아웃 발견:
- 10초, 30초, 60초 임계값 테스트
- 하트비트: 최소 2초 간격으로 NAT 매핑 유지 + 경로 실패 감지

---

## 4. 컨트롤 플레인

### 4.1 키 관리 체계

| 키 타입 | 알고리즘 | 용도 |
|---------|----------|------|
| **Machine Key** | Curve25519 | 클라이언트 식별. 컨트롤 서버와 NaCl `crypto_box` 통신 |
| **Node Key** | Curve25519 | 사용자/머신에 연결. OAuth2/SAML 인증 후 생성 |
| **Disco Key** | Curve25519 | 디스커버리 프로토콜 인증 |
| **WireGuard Key** | Curve25519 | 피어 간 터널 암호화 |

**개인키는 절대 노드를 떠나지 않는다.** 공개키만 코디네이션 서버에 등록.

### 4.2 네트워크 맵 배포

```go
type NetworkMap struct {
    SelfNode     *tailcfg.Node     // 로컬 노드 구성
    Peers        []*tailcfg.Node   // 피어 목록 (키, IP, 엔드포인트, 기능)
    DNS          DNSConfig         // 리졸버 구성
    PacketFilter []FilterRule      // ACL 규칙
    SSHPolicy    *SSHPolicy        // SSH 접근 제어
}
```

각 노드에는 **접근 가능한 피어와 규칙만** 전달 (최소 권한 원칙).

### 4.3 인증 체계

Tailscale은 자체 인증을 하지 않고 **기존 IdP (Identity Provider)에 위임**한다:

- **지원 프로토콜**: OAuth2, OIDC (OpenID Connect), SAML
- **지원 IdP**: Google/GSuite, Office365, Okta 등
- **2FA 지원**: SMS, Google Authenticator, Microsoft Authenticator
- **머신 인증서**: 사용자와 독립적으로 기기 수준 인증. 관리자가 기기에 반영구 자격증명 할당 → 올바른 사용자 자격이 있어도 미승인 기기에서는 키 등록 불가

Tailscale 서버에 **개인 식별 정보(PII)를 저장하지 않는다** — 인증은 완전히 외부 IdP가 처리.

### 4.4 보안 아키텍처: ACL과 감사 로깅

**ACL (Access Control List):**
- 코디네이션 서버에 중앙 저장, 모든 노드에 자동 배포
- 각 노드가 복호화 시점에 인바운드 패킷 필터링 → 허용되지 않은 연결은 처리 전에 차단
- **다중 방어**: (1) 코디네이션 서버가 허용된 피어의 공개키만 배포 → (2) 올바른 공개키 없이는 연결 요청 자체가 불가 → (3) 프로토콜 수준에서 공격 차단
- 레거시/미관리 서비스 보호에 특히 효과적

**감사 로깅 (이중 기록):**
- 모든 연결이 **출발지 노드 + 목적지 노드 양쪽에서** 비동기적으로 중앙 서비스에 로그
- 탐지 없이 로그 조작하려면 **두 노드를 동시에** 조작해야 함
- 실시간 스트리밍으로 로컬 조작 시간 창이 밀리초 수준으로 축소
- 메타데이터만 기록 (개인 데이터 미포함), 보존 기간 제어 가능
- 외부 분석 시스템으로 데이터 전달

### 4.5 컨트롤/데이터 플레인 분리

**컨트롤 플레인 장애 시에도 기존 데이터 연결은 유지된다.** WireGuard 터널은 이미 키가 교환된 상태이므로 코디네이션 서버 없이도 동작한다.

---

## 5. tailscaled 데몬 아키텍처

### 5.1 핵심 패키지 구조

```
tailscaled
  ├── ipn/ipnlocal.LocalBackend    <- 중앙 오케스트레이터
  |     ├── controlclient.Auto     <- 컨트롤 플레인 통신 (재연결/상태관리)
  |     |     └── controlclient.Direct  <- 저수준 HTTPS/Noise 통신
  |     ├── wgengine               <- WireGuard 엔진
  |     |     └── magicsock.Conn   <- 적응형 전송 + NAT traversal
  |     ├── net/tstun.Wrapper      <- TUN 디바이스 + ACL 필터링
  |     ├── net/dns.Manager        <- MagicDNS
  |     └── router                 <- OS 라우팅/netfilter
  └── tsd.System                   <- 의존성 주입 + 생명주기 관리
```

**구성 우선순위**: 시스템 정책 > 컨트롤 플레인 설정 > 사용자 선호도 > 구성 파일

### 5.2 바닐라 WireGuard와의 핵심 차이

| 측면 | 바닐라 WireGuard | Tailscale |
|------|-----------------|-----------|
| 피어 구성 | 정적 (`wg set`) | 동적 (코디네이션 서버) |
| 키 교환 | 수동 (대역 외) | 자동 (컨트롤 플레인) |
| NAT traversal | 없음 | STUN + DERP + Disco |
| 엔드포인트 | 고정 | 동적 전환 (magicsock) |
| 구현 | 커널 모듈 | wireguard-go (유저스페이스) |
| DNS | 없음 | MagicDNS 내장 |
| ACL | AllowedIPs만 | 세밀한 정책 기반 |
| 인증 | PSK/공개키 | OAuth2/OIDC/SAML SSO |

### 5.3 MagicDNS 3계층 아키텍처

```
dns.Manager (오케스트레이터)
  ├── resolver.Resolver (쿼리 리졸루션)
  |     ├── MagicDNS 정확 매칭
  |     ├── 서브도메인 기능 검사
  |     ├── 4via6 주소 합성
  |     └── 업스트림 포워딩
  └── resolver.forwarder
        ├── DNS over HTTPS (우선, 지연 없이 시작)
        ├── UDP DNS (500ms 후 시작)
        └── TCP 폴백
```

- **Split DNS**: 도메인 접미사 -> 리졸버 매핑. 가장 구체적인 매칭 라우트 선택
- **OS별 구성**: Linux는 `systemd-resolved` 또는 `/etc/resolv.conf` 직접 수정

### 5.4 서브넷 라우팅 구현

```bash
tailscale up --advertise-routes=10.0.0.0/8,192.168.0.0/24
```

- `router.Config.SubnetRoutes`에 광고할 서브넷 저장
- 광고된 라우트는 코디네이션 서버의 승인이 필요
- Linux에서 netfilter `FORWARD` 체인 규칙이 서브넷 간 트래픽 전달 허용
- `ip_forward` sysctl 활성화 필요 (`net.ipv4.ip_forward=1`)

**서브넷 라우트의 하이브리드 역할:**
- 메시 연결과 레거시 인프라를 결합하는 브릿지 역할
- 서브넷 라우터 노드에서 WireGuard 복호화 후 물리 네트워크로 전달
- **이 지점에서만 비암호화 패킷이 존재** — 완전 메시에서는 이 예외가 없음
- 점진적 배포의 핵심: 기존 사무실 네트워크를 Tailscale에 즉시 연결

### 5.5 출구 노드 (Exit Node) 구현

```bash
# 출구 노드 광고
tailscale up --advertise-exit-node

# 출구 노드 사용
tailscale up --exit-node=<exit-node-ip-or-hostname>
```

- 기본 라우트(`0.0.0.0/0`, `::/0`)를 배포
- `LocalRoutes`가 로컬 네트워크 트래픽의 Tailscale 우회를 보장 — 라우팅 루프 방지
- 전체 netfilter 모드(`NetfilterOn`)가 필요

### 5.6 전체 패킷 흐름

```
앱 -> tailscale0 (TUN) -> tstun.Wrapper (ACL 필터링)
  -> wireguard-go (ChaCha20-Poly1305 암호화)
  -> magicsock (경로 선택)
  -> [직접 UDP | DERP 릴레이] -> 물리 NIC -> 인터넷
```

---

## 6. 현재 환경과의 연관

### 현재 Tailscale 네트워크

| 기기 | Tailscale IP | 역할 |
|------|-------------|------|
| PC | 100.125.10.87 | 통합 뷰어 :9090 |
| Jetson Orin | 100.77.67.60 | YOLOv8 :8080 |
| RPi 3B | 100.123.127.114 | 카메라 :8080 |
| Jetson Nano | 100.125.186.100 | 카메라 :8080 |
| iPhone | 100.124.72.40 | 모바일 접속 |
| Galaxy S25 Ultra | 100.95.83.11 | 모바일 접속 |

### 향후 고려사항

- **Zybo PetaLinux**: `wireguard-go`가 유저스페이스에서 동작하므로 커널 WireGuard 모듈 불필요. `/dev/net/tun` 지원과 `ioctl(TUNSETIFF)` 가능 여부가 핵심
- **서브넷 라우팅**: 보드 수 증가 시 PC나 Orin을 서브넷 라우터로 설정하면 개별 설치 불필요
- **ACL 설정**: 6대+ 기기 연결 상태에서 보드->PC 방향만 허용하는 접근 제어 권장

---

## 참고 자료

- [Tailscale: How it works](https://tailscale.com/blog/how-tailscale-works)
- [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
- [WireGuard Protocol & Cryptography](https://www.wireguard.com/protocol/)
- [Tailscale Key Management](https://tailscale.com/blog/tailscale-key-management)
- [Control and data planes](https://tailscale.com/docs/concepts/control-data-planes)
- [Linux TUN/TAP Documentation](https://www.kernel.org/doc/html/latest/networking/tuntap.html)

---

*최종 업데이트: 2026-04-01*
