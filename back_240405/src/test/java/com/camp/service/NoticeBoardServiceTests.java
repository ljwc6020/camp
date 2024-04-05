package com.camp.service;

import java.time.LocalDate;

import com.camp.dto.NoticeBoardDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;


import lombok.extern.log4j.Log4j2;

@SpringBootTest
@Log4j2
public class NoticeBoardServiceTests {

    @Autowired
    private NoticeBoardService noticeBoardService;

    @Test
    public void testRegister() {

        NoticeBoardDTO noticeBoardDTO = NoticeBoardDTO.builder()
                .title("공지사항 등록 시간 테스트")
                .content("등록 시간")
                .writer("tester")
                .build();

        Long nbno = noticeBoardService.register(noticeBoardDTO);

        log.info("NBNO: " + nbno);

    }

    @Test
    public void testGet() {

        Long nbno = 1L;

        NoticeBoardDTO noticeBoardDTO = noticeBoardService.get(nbno);

        log.info(noticeBoardDTO);

    }

    @Test
    public void testModify(){

        NoticeBoardDTO noticeBoardDTO = NoticeBoardDTO.builder()
                .title("공지사항 서비스 수정 시간 테스트")
                .nbno(1L)
                .writer("tester")
                .content("수정 시간")
                .build();

        noticeBoardService.modify(noticeBoardDTO);

    }


    @Test
    public void testRemove(){
        noticeBoardService.remove(5L);
    }

//    @Test
//    public void testList() {
//        PageRequestDTO pageRequestDTO = PageRequestDTO.builder()
//                .page(1)
//                .size(10)
//                .build();
//        PageResponseDTO<NoticeBoardDTO> response = noticeBoardService.list(pageRequestDTO);
//        log.info(response);
//    }

}