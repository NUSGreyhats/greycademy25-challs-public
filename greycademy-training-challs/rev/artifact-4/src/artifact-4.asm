check:
    push rbp
    mov  rbp, rsp
    sub  rsp, 2
    mov  A, [edi+1000]
    mov  [rbp-1], A
    mov  A, [esi+2000]
    mov  [rbp-2], A
    mov  A, [rbp-1]
    mov  B, [rbp-2]
    sete eax, A, B
    mov  rsp, rbp
    pop  rbp
    ret

main:
    mov  edi, 0
    mov  esi, 8
    call check
    inc  edi
    mov  esi, 15
