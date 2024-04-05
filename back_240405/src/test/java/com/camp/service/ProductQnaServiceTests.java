package com.camp.service;

import com.camp.domain.ProductQna;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductQnaDTO;
import com.camp.repository.ProductQnaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ProductQnaServiceTests {

    @Mock
    private ProductQnaRepository productQnaRepository;

    @Mock
    private ModelMapper modelMapper;

    @InjectMocks
    private ProductQnaServiceImpl productQnaService;

    private ProductQnaDTO productQnaDTO;

    private ProductQna productQna;

    @BeforeEach
    void setUp() {
        // 테스트에서 사용할 가짜 데이터 설정
        productQnaDTO = new ProductQnaDTO();
//        productQnaDTO.setId(1L);
        productQnaDTO.setQuestion("Test question?");
        productQnaDTO.setAnswer("Test answer");

        productQna = new ProductQna();
        productQna.setQno(1L);
        productQna.setQuestion("Test question?");
        productQna.setAnswer("Test answer");
        productQna.setAskedAt(LocalDateTime.now());
        productQna.setAnsweredAt(LocalDateTime.now());
    }

    @Test
    void register() {
        // 새로운 상품 Q&A를 등록하는 테스트
        // given
        when(modelMapper.map(productQnaDTO, ProductQna.class)).thenReturn(productQna);
        when(productQnaRepository.save(productQna)).thenReturn(productQna);

        // when
        Long qnaId = productQnaService.register(productQnaDTO);

        // then
        assertNotNull(qnaId);
        assertEquals(productQna.getQno(), qnaId);
        verify(productQnaRepository, times(1)).save(productQna);
    }

    @Test
    void get() {
        // 특정 상품 Q&A를 조회하는 테스트
        // given
        when(productQnaRepository.findById(1L)).thenReturn(Optional.of(productQna));
        when(modelMapper.map(productQna, ProductQnaDTO.class)).thenReturn(productQnaDTO);

        // when
        ProductQnaDTO retrievedQna = productQnaService.get(1L);

        // then
        assertNotNull(retrievedQna);
//        assertEquals(productQnaDTO.getId(), retrievedQna.getId());
        assertEquals(productQnaDTO.getQuestion(), retrievedQna.getQuestion());
        assertEquals(productQnaDTO.getAnswer(), retrievedQna.getAnswer());
        verify(productQnaRepository, times(1)).findById(1L);
    }

    @Test
    void modify() {
        // 상품 Q&A를 수정하는 테스트
        // given
        when(productQnaRepository.findById(1L)).thenReturn(Optional.of(productQna));
        when(productQnaRepository.save(productQna)).thenReturn(productQna);

        // when
        productQnaDTO.setAnswer("Modified answer");
        productQnaService.modify(productQnaDTO);

        // then
        assertEquals(productQnaDTO.getAnswer(), productQna.getAnswer());
        verify(productQnaRepository, times(1)).save(productQna);
    }

    @Test
    void remove() {
        // 상품 Q&A를 삭제하는 테스트
        // when
        productQnaService.remove(1L);

        // then
        verify(productQnaRepository, times(1)).deleteById(1L);
    }


//    @Test
//    void registerReply_Success() {
//        // 부모 Q&A 엔티티 생성
//        ProductQna parentQna = new ProductQna();
//        parentQna.setQno(1L);
//
//        // 대댓글 DTO 생성
////        ProductQnaDTO.ProductQnaReplyDTO replyDTO = new ProductQnaDTO.ProductQnaReplyDTO();
////        replyDTO.setReplyContent("This is a reply.");
//
//        // Mocking - 부모 Q&A 조회 결과
//        when(productQnaRepository.findById(1L)).thenReturn(Optional.of(parentQna));
//
//        // 테스트 대상 메서드 호출
////        productQnaService.registerReply(1L, replyDTO);
//
////        // 대댓글 엔티티 생성 확인
////        verify(modelMapper, times(1)).map(eq(replyDTO), eq(ProductQna.ProductQnaReply.class));
////
////        // 부모 Q&A에 대댓글 추가 확인
////        verify(productQnaRepository, times(1)).save(parentQna);
////        // 대댓글이 부모 Q&A에 추가되었는지 확인
////        assertTrue(parentQna.getReplies().size() > 0, "Reply was not added to parent Q&A.");
//    }


}
