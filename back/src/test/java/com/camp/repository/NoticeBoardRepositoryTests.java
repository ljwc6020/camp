package com.camp.repository;

import java.time.LocalDate;

import com.camp.domain.NoticeBoard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;



import lombok.extern.log4j.Log4j2;

@SpringBootTest
@Log4j2
public class NoticeBoardRepositoryTests {

    @Autowired
    private NoticeBoardRepository noticeBoardRepository;


    @Test
    public void testInsert() {

        for (int i = 1; i <= 5; i++) {

            NoticeBoard noticeBoard = NoticeBoard.builder()
                    .title("Title..." + i)
                    .writer("user00")
                    .content("A")
                    .build();
            log.info(noticeBoard);
            noticeBoardRepository.save(noticeBoard);
        }
    }

    @Test
    public void testModify() {

        Long nbno = 1L;

        java.util.Optional<NoticeBoard> result = noticeBoardRepository.findById(nbno); //java.util 패키지의 Optional

        NoticeBoard noticeBoard = result.orElseThrow();
        noticeBoard.changeTitle("Modified 1...");
        log.info(noticeBoard);
        noticeBoardRepository.save(noticeBoard);

    }
}