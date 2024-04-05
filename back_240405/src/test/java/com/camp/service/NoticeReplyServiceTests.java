package com.camp.service;

import com.camp.dto.NoticeReplyDTO;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class NoticeReplyServiceTests {

    @Autowired
    private NoticeReplyService replyService;

    @Test
    public void testRegister(){

        NoticeReplyDTO replyDTO = NoticeReplyDTO.builder()
                .replyText("ReplyDTO Text")
                .replyer("replyer")
                .nbno(9L)
                .build();

        log.info(replyService.register(replyDTO));
    }
}