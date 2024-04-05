package com.camp.repository;


import com.camp.domain.NoticeBoard;
import com.camp.domain.NoticeReply;
import jakarta.transaction.Transactional;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.annotation.Commit;

@SpringBootTest
@Log4j2
public class NoticeReplyRepositoryTests {

    @Autowired
    private NoticeReplyRepository replyRepository;

    @Autowired
    private NoticeBoardRepository boardRepository;

    @Test
    public void testInsert() {

        //실제DB에 있는 bno
        Long nbno = 5L;

        NoticeBoard board = NoticeBoard.builder().nbno(nbno).build();

        NoticeReply reply = NoticeReply.builder()
                .noticeBoard(board)
                .replyText("저두요~")
                .replyer("replyer03")
                .build();

        replyRepository.save(reply);
    }

    @Transactional// 데이터베이스 연산을 하나의 작업 단위로 묶는 역할.
    @Test
    public void testNoticeBoardReplies() {

        Long nbno = 9L;

        Pageable pageable = PageRequest.of(0, 10,
                Sort.by("nrno").descending());

        Page<NoticeReply> result = replyRepository.listOfBoard(nbno, pageable);

        result.getContent().forEach(reply -> {
            log.info(reply);
        });

    }

    @Test
    @Transactional
    @Commit
    public  void testRemoveAll(){

        Long nbno = 9L;

        replyRepository.deleteByNoticeBoardNbno(nbno);

    }

}
