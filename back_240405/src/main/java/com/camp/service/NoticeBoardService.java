package com.camp.service;

import com.camp.dto.NoticeBoardDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;

public interface NoticeBoardService {

    Long register(NoticeBoardDTO noticeBoardDTO);

    NoticeBoardDTO get(Long nbno);

    void modify(NoticeBoardDTO noticeBoardDTO);

    void remove(Long nbno);

    public PageResponseDTO<NoticeBoardDTO> list(String writer, String title, PageRequestDTO pageRequestDTO );

    public void updateTotalReplies(Long nbno);

}
