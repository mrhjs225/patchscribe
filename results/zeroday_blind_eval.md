
## Case: CWE-125___CVE-2024-36931.c___1-41___14.c

### Option A

### Vulnerability Fix Explanation

1. **무엇이 취약점을 유발했는가 (what)**
   - `buffer = vmemdup_user(buf, lbuf);` 호출이 사용자 입력을 커널 메모리로 복제할 때 **NULL 종료 문자(NUL) 보장 없이 복제**한다.
   - 복제된 버퍼가 NUL‑terminated가 아니면 `sscanf()` 가 문자열 끝을 찾지 못하고 메모리 경계를 넘어 읽어들일 수 있어 **버퍼 오버플로우** 및 **정보 누출**이 발생한다.

2. **패치가 코드에 어떤 변화를 주었는가 (how)**
   - `vmemdup_user` 를 `memdup_user_nul` 로 교체하였다.
   - `memdup_user_nul(buf, lbuf)` 은 복제 과정에서 **버퍼 끝에 자동으로 NUL 문자**를 추가한다.

3. **그 변화가 왜 취약점을 제거하는가 (why)**
   - NUL‑terminated 버퍼를 확보함으로써 `sscanf(buffer, ...)` 가 문자열 파싱을 수행할 때 **정확한 종료 지점을 인식**한다.
   - 파싱 과정에서 메모리 경계를 초과하는 읽기가 발생하지 않으므로 **버퍼 오버플로우**와 그에 따른 권한 상승·정보 유출 위험이 사라진다.

4. **요약**
   - 원인: NUL 종료가 보장되지 않은 사용자 버퍼 복제 (`vmemdup_user`).
   - 변경: 안전한 복제 함수 `memdup_user_nul` 로 교체.
   - 효과: 복제된 버퍼가 항상 NUL‑terminated가 되어 `sscanf` 의 안전한 파싱이 보장되고, 기존 메모리 오버플로우 취약점이 근본적으로 차단된다.




### Option B

### Vulnerability Fix Explanation

1. **무엇이 취약점을 유발했는가 (what)**
   - `buffer = vmemdup_user(buf, lbuf);` 로 사용자 공간 데이터를 커널 버퍼에 복제했지만, **NUL 종료가 보장되지 않음**.
   - 이후 `sscanf(buffer, ...)` 가 문자열 파싱을 수행하면서 **버퍼 끝을 넘어 읽기**가 발생할 수 있어 메모리 오버플로우·정보 누출 위험이 존재함.
   - 또한 `vmemdup_user` 는 페이지를 직접 매핑하는 방식이므로, 복제된 메모리가 사용자 페이지와 동일한 물리 페이지를 공유해 **사용자‑커널 메모리 경계 검증 우회** 가능성이 있었다.

2. **패치가 코드에 어떤 변화를 주었는가 (how)**
   - `vmemdup_user` 를 **`memdup_user_nul(buf, lbuf)`** 로 교체하였다.
   - `memdup_user_nul` 은 복제 시 자동으로 **NUL 문자(`'\0'`)를 추가**해 문자열 안전성을 확보한다.
   - 복제된 버퍼에 대한 해제 방식을 `kvfree(buffer);` 로 명시적으로 수행하였다.
   - 기존 흐름은 유지하면서, `static_branch_likely(&cio_inject_enabled)` 체크와 오류 반환 로직은 그대로 보존하였다.

3. **그 변화가 왜 취약점을 제거하는가 (why)**
   - **NUL 종료 보장**으로 `sscanf` 가 버퍼 경계를 초과해 읽는 상황이 사라진다. 따라서 메모리 오버플로우·읽기 취약이 차단된다.
   - `memdup_user_nul` 은 내부적으로 `copy_from_user` 를 사용해 **사용자 페이지를 직접 매핑하지 않으며**, 복제된 메모리는 완전히 새로운 커널 페이지에 저장된다. 이는 사용자‑커널 메모리 공유에 따른 권한 상승·정보 누출 위험을 제거한다.
   - 명시적인 `kvfree` 로 메모리 해제를 보장해 잠재적인 메모리 누수도 방지한다.

결과적으로, 패치는 문자열 파싱 시 안전한 메모리 복제와 해제를 구현함으로써 원래 `vmemdup_user` 사용으로 인한 메모리 오버플로우와 권한 우회 취약을 완전히 제거한다.




### Option C

### Vulnerability Fix Explanation

1. **무엇이 취약점을 유발했는가 (what)**
   - 기존 코드에서는 `buffer = vmemdup_user(buf, lbuf);` 로 사용자 공간 데이터를 커널에 복제했지만, 복제된 메모리는 NUL‑terminator가 보장되지 않는다.
   - 이후 `sscanf(buffer, "%x %x %x %x %x %x %x", …)` 를 사용해 포맷 문자열 파싱을 수행하면서, NUL‑terminator가 없으면 `sscanf` 가 버퍼 끝을 넘어 읽어 **버퍼 오버플로우** 혹은 **메모리 오염**이 발생할 수 있다.

2. **패치가 코드에 어떤 변화를 주었는가 (how)**
   - `vmemdup_user` 를 `memdup_user_nul(buf, lbuf)` 로 교체하여 복제된 버퍼에 자동으로 NUL‑terminator 를 추가한다.
   - 복제 실패 시 `IS_ERR(buffer)` 로 오류를 검사하고 `-ENOMEM` 을 반환한다.
   - 사용이 끝난 버퍼를 `kvfree(buffer)` 로 해제하여 메모리 누수를 방지한다.
   - 포맷 파싱 결과가 7개가 아니면 `-EINVAL` 을 반환하도록 검증 로직을 유지한다.

3. **그 변화가 왜 취약점을 제거하는가 (why)**
   - NUL‑terminator 가 보장된 버퍼는 `sscanf` 가 문자열 끝을 정확히 인식하므로, 입력 길이가 `lbuf` 를 초과하더라도 읽기 범위가 버퍼 경계를 넘어가지 않는다.
   - 따라서 **버퍼 오버플로우**가 발생하지 않으며, 커널 메모리의 무결성이 유지된다.
   - 추가된 오류 검사와 `kvfree` 로 메모리 할당/해제 오류도 방지되어 전체적인 안정성이 향상된다.




---
