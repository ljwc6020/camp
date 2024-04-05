package com.camp.repository;

import com.camp.domain.Image;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.text.html.Option;
import java.util.List;
import java.util.Optional;

public interface ImageRepository  extends JpaRepository<Image, String> {

    Optional<Image> findByPrediction(String prediction);
}
