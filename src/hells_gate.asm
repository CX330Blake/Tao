; MASM version
; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

; .data
; 	wSystemCall DWORD 000h
;
; .code 
; 	HellsGate PROC
; 		mov wSystemCall, 000h
; 		mov wSystemCall, ecx
; 		ret
; 	HellsGate ENDP
;
; 	HellDescent PROC
; 		mov r10, rcx
; 		mov eax, wSystemCall
;
; 		syscall
; 		ret
; 	HellDescent ENDP
; end

; NASM version
BITS 64

section .data
    wSystemCall: dq 0

section .text
global hells_gate
global hell_descent

hells_gate:
    mov dword [rel wSystemCall], ecx
    ret

hell_descent:
    mov r10, rcx
    mov eax, dword [rel wSystemCall]
    syscall
    ret

