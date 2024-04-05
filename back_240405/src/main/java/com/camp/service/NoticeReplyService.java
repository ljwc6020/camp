package com.camp.service;

import com.camp.dto.NoticeReplyDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;

public interface NoticeReplyService {

    Long register(NoticeReplyDTO noticeReplyDTO);

    NoticeReplyDTO read(Long nrno);

    void modify(NoticeReplyDTO noticeReplyDTO);

    void  remove(Long nrno);

    // 실제 반환되어야 하는 타입은 NoticeReply이 아니라 NoticeReplyDTO타입이다.
    PageResponseDTO<NoticeReplyDTO> getListOfBoard(Long nbno, PageRequestDTO pageRequestDTO);

}
