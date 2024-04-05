package com.camp.controller;

import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductQnaDTO;
import com.camp.service.ProductQnaService;
import com.camp.util.CustomFileUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/qna")
@RequiredArgsConstructor
@Log4j2
public class ProductQnaController {

    private final ProductQnaService productQnaService;
    private final CustomFileUtil customFileUtil;


    // 새로운 상품 Q&A 등록을 처리하는 메서드
    @PostMapping("/")
    public ResponseEntity<Long> register(@RequestBody ProductQnaDTO productQnaDTO) {
        Long qnaId = productQnaService.register(productQnaDTO);
        return new ResponseEntity<>(qnaId, HttpStatus.CREATED);
    }


    // 특정 ID를 가진 상품 Q&A를 조회하는 메서드
    @GetMapping("/read/{qno}")
    public ResponseEntity<ProductQnaDTO> get(@PathVariable Long qno) {
        ProductQnaDTO productQnaDTO = productQnaService.get(qno);
        return ResponseEntity.ok(productQnaDTO);
    }


    // 특정 ID를 가진 상품 Q&A를 수정하는 메서드
    @PreAuthorize("#productQnaDTO.authorName == authentication.name or hasAnyRole('ADMIN')")
    @PutMapping("/{qno}")
    public ResponseEntity<Void> modify(@PathVariable Long qno, @RequestBody ProductQnaDTO productQnaDTO) {
        productQnaDTO.setQno(qno);
        productQnaService.modify(productQnaDTO);
        return ResponseEntity.ok().build();
    }


    // 특정 ID를 가진 상품 Q&A를 삭제하는 메서드
    @PreAuthorize("#productQnaDTO.authorName == authentication.name")
    @DeleteMapping("/{qno}")
    public ResponseEntity<Void> remove(@PathVariable Long qno,
                                       @RequestBody ProductQnaDTO productQnaDTO) {
        productQnaService.remove(qno);
        return ResponseEntity.noContent().build();
    }


    // 특정 상품에 대한 Q&A 목록을 조회하는 메서드
    @GetMapping("/list/{pno}")
    public ResponseEntity<PageResponseDTO<ProductQnaDTO>> getList(@PathVariable(name="pno") Long pno, PageRequestDTO pageRequestDTO) {
        PageResponseDTO<ProductQnaDTO> responseDTO = productQnaService.getQnaList(pno, pageRequestDTO);
        return ResponseEntity.ok(responseDTO);
    }

}
