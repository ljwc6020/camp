package com.camp.repository;

import com.camp.domain.ProductQna;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.annotation.Commit;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

import lombok.extern.log4j.Log4j2;

@SpringBootTest
@Log4j2
public class ProductQnaRepositoryTests {

    @Autowired
    private ProductQnaRepository productQnaRepository;

    @Test
    public void testInsert() {
        ProductQna qna = ProductQna.builder()
                .question("새로운 질문")
                .authorName("작성자")
                .build();

        ProductQna savedQna = productQnaRepository.save(qna);
        assertNotNull(savedQna.getQno(), "저장된 QnA의 ID는 null이 아니어야 합니다.");
        log.info("새로운 QnA 등록: " + savedQna);
    }

    @Transactional
    @Test
    public void testRead() {
        // 저장 후 조회 테스트를 위해 먼저 새로운 QnA를 등록
        ProductQna qna = ProductQna.builder()
                .question("테스트 질문")
                .authorName("테스트 작성자")
                .build();
        ProductQna savedQna = productQnaRepository.save(qna);

        Optional<ProductQna> result = productQnaRepository.findById(savedQna.getQno());
        ProductQna foundQna = result.orElseThrow();

        assertEquals("테스트 질문", foundQna.getQuestion(), "조회된 QnA의 질문이 저장한 질문과 일치해야 합니다.");
        assertEquals("테스트 작성자", foundQna.getAuthorName(), "조회된 QnA의 작성자가 저장한 작성자와 일치해야 합니다.");
        log.info("QnA 조회: " + foundQna);
    }

//    @Transactional
//    @Test
//    public void testInsertReply() {
//        // 부모 Q&A 저장
//        ProductQna parentQna = ProductQna.builder()
//                .question("부모 질문")
//                .authorName("부모 작성자")
//                .build();
//        ProductQna savedParentQna = productQnaRepository.save(parentQna);

//        // 대댓글 저장
//        ProductQna reply = ProductQna.builder()
//                .question("대댓글")
//                .authorName("대댓글 작성자")
//                .parentQna(savedParentQna)
//                .build();
//        ProductQna savedReply = productQnaRepository.save(reply);
//
//        // 저장된 대댓글 조회
//        Optional<ProductQna> foundReplyOptional = productQnaRepository.findById(savedReply.getQno());
//        ProductQna foundReply = foundReplyOptional.orElse(null);
//
//        // 대댓글이 저장되었는지 확인
//        assertNotNull(foundReply, "저장된 대댓글은 null이 아니어야 합니다.");
//        assertEquals("대댓글", foundReply.getQuestion(), "저장된 대댓글의 질문은 '대댓글'이어야 합니다.");
    }
//}

