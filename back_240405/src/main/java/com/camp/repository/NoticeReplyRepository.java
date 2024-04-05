package com.camp.repository;

import com.camp.domain.NoticeReply;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface NoticeReplyRepository extends JpaRepository<NoticeReply, Long> {

    @Query("select nr from NoticeReply nr where nr.noticeBoard.nbno = :nbno")
    Page<NoticeReply> listOfBoard(@Param("nbno") Long nbno, Pageable pageable);

    void deleteByNoticeBoardNbno(Long nbno);

    // nrno 를 이용하여 nbno 를 알아오는 쿼리문
    @Query("SELECT nr.noticeBoard.nbno FROM NoticeReply nr WHERE nr.nrno = :nrno")
    Optional<Long> findNbnoByNrno(@Param("nrno") Long nrno);


}